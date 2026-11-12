using Lib3dsKit.IO;
using ZstdSharp;

namespace Lib3dsKit.Z3ds;

/// <summary>
/// The file a Z3DS file holds, as a read-only seekable stream. Only the frames that are read are
/// decompressed (one is kept in memory, at most 32 MiB for a CIA), so the rest of the library can
/// read a .zcci, .zcia or .zcxi as if it were the plain file.
/// </summary>
public sealed class Z3dsReadStream : VirtualStream
{
    private readonly Stream _base;
    private readonly bool _ownsBase;
    private readonly List<SeekFrame> _frames;
    private readonly Decompressor _decompressor = new();
    private readonly long _length;
    private byte[] _compressed = [];
    private byte[] _plain = [];
    private int _cached = -1;

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
        var frame = _frames[index];
        if (_compressed.Length < frame.CompressedSize) _compressed = new byte[frame.CompressedSize];
        if (_plain.Length < frame.DecompressedSize) _plain = new byte[frame.DecompressedSize];
        _cached = -1;
        ReadExactlyAt(_base, frame.CompressedOffset, _compressed.AsSpan(0, frame.CompressedSize));
        int written;
        try
        {
            written = _decompressor.Unwrap(_compressed.AsSpan(0, frame.CompressedSize), _plain.AsSpan(0, frame.DecompressedSize));
        }
        catch (ZstdException ex)
        {
            throw new CtrFormatException($"Z3DS frame {index} is damaged: {ex.Message}");
        }
        if (written != frame.DecompressedSize)
            throw new CtrFormatException($"Z3DS frame {index} decompressed to {written} bytes, not {frame.DecompressedSize}.");
        _cached = index;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _decompressor.Dispose();
            if (_ownsBase) _base.Dispose();
        }
        base.Dispose(disposing);
    }
}
