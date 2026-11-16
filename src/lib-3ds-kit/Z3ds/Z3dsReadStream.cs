using System.Buffers;
using System.Collections.Concurrent;
using Lib3dsKit.IO;
using ZstdSharp;

namespace Lib3dsKit.Z3ds;

/// <summary>
/// The file a Z3DS file holds, as a read-only seekable stream. Only the frames that are read are
/// decompressed (one is kept in memory, at most 32 MiB for a CIA), so the rest of the library can
/// read a .zcci, .zcia or .zcxi as if it were the plain file. Once it's read frame after frame, the
/// next few frames (up to about 64 MiB) are decompressed ahead on the thread pool.
/// </summary>
public sealed class Z3dsReadStream : VirtualStream
{
    private const int AheadBytes = 64 * 1024 * 1024;

    private readonly Stream _base;
    private readonly bool _ownsBase;
    private readonly List<SeekFrame> _frames;
    private readonly Decompressor _decompressor = new();
    private readonly ConcurrentBag<Decompressor> _aheadDecompressors = new();
    private readonly Queue<(int Index, byte[] Plain, PoolJob<int> Done)> _ahead = new();
    private readonly int _window;
    private readonly long _length;
    private byte[] _compressed = [];
    private byte[] _plain = [];
    private int _cached = -1;
    private int _last = -1;

    /// <param name="baseStream">The Z3DS file; read from its start.</param>
    /// <param name="ownsBase">Dispose <paramref name="baseStream"/> with this stream.</param>
    public Z3dsReadStream(Stream baseStream, bool ownsBase = true)
    {
        _base = baseStream;
        _ownsBase = ownsBase;
        Header = Z3dsFile.ReadHeader(baseStream);
        long dataLength = Header.CompressedSize > 0 ? (long)Header.CompressedSize : baseStream.Length - Header.DataOffset;
        if (Header.DataOffset + dataLength > baseStream.Length) throw new CtrFormatException("Z3DS file is truncated.");
        _frames = SeekTable.Read(baseStream, Header.DataOffset, dataLength);
        _length = _frames.Count == 0 ? 0 : _frames[^1].DecompressedOffset + _frames[^1].DecompressedSize;
        if ((ulong)_length != Header.UncompressedSize)
            throw new CtrFormatException($"Z3DS seek table holds {_length} bytes but the header says {Header.UncompressedSize}.");
        int largest = _frames.Count == 0 ? 1 : Math.Max(1, _frames.Max(f => f.DecompressedSize));
        _window = Math.Clamp(AheadBytes / largest, 1, Math.Max(1, Environment.ProcessorCount));
    }

    public Z3dsHeader Header { get; }

    /// <summary>The number of zstd frames.</summary>
    public int FrameCount => _frames.Count;

    public override long Length => _length;

    protected override void ReadAt(long position, Span<byte> buffer)
    {
        while (buffer.Length > 0)
        {
            int i = FrameAt(position);
            var frame = _frames[i];
            Load(i);
            int inFrame = (int)(position - frame.DecompressedOffset);
            int n = Math.Min(buffer.Length, frame.DecompressedSize - inFrame);
            _plain.AsSpan(inFrame, n).CopyTo(buffer);
            buffer = buffer[n..];
            position += n;
        }
    }

    private int FrameAt(long position)
    {
        if (_cached >= 0 && position >= _frames[_cached].DecompressedOffset
                         && position < _frames[_cached].DecompressedOffset + _frames[_cached].DecompressedSize)
            return _cached;
        int lo = 0, hi = _frames.Count - 1;
        while (lo < hi)
        {
            int mid = (lo + hi + 1) / 2;
            if (_frames[mid].DecompressedOffset <= position) lo = mid; else hi = mid - 1;
        }
        return lo;
    }

    private void Load(int index)
    {
        if (index == _cached) return;
        // Two frames in a row: a single read at the start (headers) doesn't set off the read-ahead.
        bool sequential = _last >= 0 && index == _last + 1;
        _last = index;
        _cached = -1;
        if (_ahead.Count > 0 && _ahead.Peek().Index == index) TakeAhead();
        else
        {
            DropAhead(); // a jump: what was decompressed ahead is of no use
            Decompress(index);
        }
        _cached = index;
        if (sequential) ReadAhead(index);
    }

    private void Decompress(int index)
    {
        var frame = _frames[index];
        if (_compressed.Length < frame.CompressedSize) _compressed = new byte[frame.CompressedSize];
        if (_plain.Length < frame.DecompressedSize) ReplacePlain(ArrayPool<byte>.Shared.Rent(frame.DecompressedSize));
        ReadExactlyAt(_base, frame.CompressedOffset, _compressed.AsSpan(0, frame.CompressedSize));
        int written;
        try
        {
            written = _decompressor.Unwrap(_compressed.AsSpan(0, frame.CompressedSize), _plain.AsSpan(0, frame.DecompressedSize));
        }
        catch (ZstdException ex)
        {
            throw Damaged(index, ex);
        }
        Check(index, written);
    }

    /// <summary>Queues the frames after <paramref name="index"/> to be decompressed on the thread pool.</summary>
    private void ReadAhead(int index)
    {
        int next = _ahead.Count > 0 ? _ahead.Last().Index + 1 : index + 1;
        for (; next < _frames.Count && next <= index + _window; next++)
        {
            var frame = _frames[next];
            // The compressed bytes are read here, so only this thread touches the base stream.
            byte[] packed = ArrayPool<byte>.Shared.Rent(frame.CompressedSize);
            byte[] plain = ArrayPool<byte>.Shared.Rent(frame.DecompressedSize);
            try { ReadExactlyAt(_base, frame.CompressedOffset, packed.AsSpan(0, frame.CompressedSize)); }
            catch
            {
                ArrayPool<byte>.Shared.Return(packed);
                ArrayPool<byte>.Shared.Return(plain);
                throw;
            }
            var done = new PoolJob<int>(() =>
            {
                if (!_aheadDecompressors.TryTake(out var d)) d = new Decompressor();
                try { return d.Unwrap(packed.AsSpan(0, frame.CompressedSize), plain.AsSpan(0, frame.DecompressedSize)); }
                finally
                {
                    _aheadDecompressors.Add(d);
                    ArrayPool<byte>.Shared.Return(packed);
                }
            });
            _ahead.Enqueue((next, plain, done));
        }
    }

    private void TakeAhead()
    {
        var (index, plain, done) = _ahead.Dequeue();
        ReplacePlain(plain);
        int written;
        try { written = done.Wait(); }
        catch (ZstdException ex) { throw Damaged(index, ex); }
        Check(index, written);
    }

    /// <summary>Waits for every frame being decompressed ahead and gives its buffer back.</summary>
    private void DropAhead()
    {
        while (_ahead.Count > 0)
        {
            var (_, plain, done) = _ahead.Dequeue();
            done.CancelOrWait(); // of no use now: not started, it's dropped; damaged or not, it's discarded
            ArrayPool<byte>.Shared.Return(plain);
        }
    }

    private void ReplacePlain(byte[] plain)
    {
        if (_plain.Length > 0) ArrayPool<byte>.Shared.Return(_plain);
        _plain = plain;
    }

    private void Check(int index, int written)
    {
        if (written != _frames[index].DecompressedSize)
            throw new CtrFormatException($"Z3DS frame {index} decompressed to {written} bytes, not {_frames[index].DecompressedSize}.");
    }

    private static CtrFormatException Damaged(int index, ZstdException ex) =>
        new($"Z3DS frame {index} is damaged: {ex.Message}");

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            DropAhead();
            ReplacePlain([]);
            _cached = -1;
            _decompressor.Dispose();
            while (_aheadDecompressors.TryTake(out var d)) d.Dispose();
            if (_ownsBase) _base.Dispose();
        }
        base.Dispose(disposing);
    }
}
