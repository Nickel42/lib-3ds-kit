using System.Buffers;
using System.Collections.Concurrent;
using Lib3dsKit.IO;
using ZstdSharp;

namespace Lib3dsKit.Z3ds;

/// <summary>
/// Writes a Z3DS file: what's written to this stream is cut into frames, each compressed as its own
/// zstd frame on the thread pool while the caller goes on writing, and written to the destination in order.
/// <see cref="Finish"/> adds the seek table and goes back to fill in the header, so the destination must be seekable.
/// </summary>
public sealed class Z3dsWriteStream : Stream
{
    private readonly Stream _dest;
    private readonly int _frameSize;
    private readonly int _level;
    private readonly byte[] _magic;
    private readonly uint _metadataSize;
    private readonly long _headerOffset;
    private readonly Queue<(PoolJob<int> Packed, byte[] Plain, byte[] Out, int Length)> _inFlight = new();
    private readonly ConcurrentBag<Compressor> _compressors = new();
    private readonly int _window;
    private readonly int _bound;
    private readonly List<(int Compressed, int Decompressed)> _frames = new();
    private byte[] _current;
    private int _fill;
    private long _written;
    private long _compressedBytes;
    private bool _finished;
    private bool _failed;

    /// <param name="destination">Seekable; the Z3DS file is written from its current position.</param>
    /// <param name="type">What's being compressed: sets the underlying magic Azahar reads.</param>
    /// <param name="frameSize">Bytes per frame; 0 for Azahar's size for <paramref name="type"/>.</param>
    /// <param name="level">zstd level (Azahar uses 3).</param>
    /// <param name="metadata">Extra metadata items; "compressor", "date" and "maxframesize" are added.</param>
    public Z3dsWriteStream(Stream destination, CtrFileType type, int frameSize = 0, int level = 3,
        IEnumerable<KeyValuePair<string, byte[]>>? metadata = null)
    {
        if (!destination.CanSeek || !destination.CanWrite) throw new ArgumentException("The destination must be seekable and writable.", nameof(destination));
        _dest = destination;
        _magic = Z3dsFile.UnderlyingMagicOf(type);
        _frameSize = frameSize > 0 ? frameSize : Z3dsFile.FrameSizeFor(type);
        _level = level;
        // Up to two frames per core are compressed at once, and at most about 256 MiB of input is in flight.
        _window = Math.Max(1, Math.Min(Environment.ProcessorCount * 2, 256 * 1024 * 1024 / _frameSize));
        _bound = Compressor.GetCompressBound(_frameSize);
        _current = ArrayPool<byte>.Shared.Rent(_frameSize);

        var items = new Dictionary<string, byte[]>
        {
            ["compressor"] = "lib-3ds-kit"u8.ToArray(),
            ["date"] = System.Text.Encoding.ASCII.GetBytes(DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")),
            ["maxframesize"] = System.Text.Encoding.ASCII.GetBytes(_frameSize.ToString(System.Globalization.CultureInfo.InvariantCulture)),
        };
        if (metadata is not null) foreach (var (k, v) in metadata) items[k] = v;
        var meta = Z3dsFile.BuildMetadata(items);
        _metadataSize = (uint)meta.Length;
        _headerOffset = destination.Position;
        destination.Write(Z3dsFile.BuildHeader(_magic, _metadataSize, 0, 0)); // filled in by Finish
        destination.Write(meta);
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => !_finished;

    /// <summary>Bytes written so far (before compression).</summary>
    public override long Length => _written;

    public override long Position
    {
        get => _written;
        set => throw new NotSupportedException();
    }

    /// <summary>Bytes of compressed data written so far.</summary>
    public long CompressedLength => _compressedBytes;

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        if (_finished) throw new ObjectDisposedException(nameof(Z3dsWriteStream));
        while (buffer.Length > 0)
        {
            int n = Math.Min(buffer.Length, _frameSize - _fill);
            buffer[..n].CopyTo(_current.AsSpan(_fill));
            _fill += n;
            _written += n;
            buffer = buffer[n..];
            if (_fill == _frameSize) QueueFrame();
        }
    }

    private void QueueFrame()
    {
        // The last frame may be partly full; its length travels with it.
        if (_inFlight.Count >= _window) WriteOldest();
        byte[] plain = _current, packed = ArrayPool<byte>.Shared.Rent(_bound);
        int length = _fill;
        _current = ArrayPool<byte>.Shared.Rent(_frameSize);
        _fill = 0;
        var task = new PoolJob<int>(() =>
        {
            if (!_compressors.TryTake(out var c)) c = new Compressor(_level);
            try { return c.Wrap(plain.AsSpan(0, length), packed); }
            finally { _compressors.Add(c); }
        });
        _inFlight.Enqueue((task, plain, packed, length));
    }

    /// <summary>Waits for the oldest frame in flight and writes it.</summary>
    private void WriteOldest()
    {
        var (task, plain, packed, length) = _inFlight.Peek();
        int size;
        try { size = task.Wait(); }
        catch { _failed = true; throw; }
        _inFlight.Dequeue();
        _dest.Write(packed, 0, size);
        _frames.Add((size, length));
        _compressedBytes += size;
        ArrayPool<byte>.Shared.Return(plain);
        ArrayPool<byte>.Shared.Return(packed);
    }

    /// <summary>Compresses what's left, writes the seek table and the header. Called by Dispose if not before.</summary>
    public void Finish()
    {
        if (_finished) return;
        _finished = true;
        try
        {
            if (_fill > 0) QueueFrame();
            while (_inFlight.Count > 0) WriteOldest();
            var table = SeekTable.Build(_frames);
            _dest.Write(table);
            _compressedBytes += table.Length;
            long end = _dest.Position;
            _dest.Position = _headerOffset;
            _dest.Write(Z3dsFile.BuildHeader(_magic, _metadataSize, (ulong)_compressedBytes, (ulong)_written));
            _dest.Position = end;
        }
        finally
        {
            Release();
        }
    }

    /// <summary>Lets the frames still in flight finish (after a failure), then gives back buffers and compressors.</summary>
    private void Release()
    {
        while (_inFlight.Count > 0)
        {
            var (task, plain, packed, _) = _inFlight.Dequeue();
            try { task.Wait(); } catch { } // already failed or being discarded
            ArrayPool<byte>.Shared.Return(plain);
            ArrayPool<byte>.Shared.Return(packed);
        }
        ArrayPool<byte>.Shared.Return(_current);
        _current = [];
        while (_compressors.TryTake(out var c)) c.Dispose();
    }

    public override void Flush() { }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_finished)
        {
            if (_failed) { _finished = true; Release(); } // nothing more is written after a frame failed
            else Finish();
        }
        base.Dispose(disposing);
    }
}
