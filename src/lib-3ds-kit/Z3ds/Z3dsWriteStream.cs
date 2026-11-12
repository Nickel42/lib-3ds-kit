using System.Buffers;
using ZstdSharp;

namespace Lib3dsKit.Z3ds;

/// <summary>
/// Writes a Z3DS file: what's written to this stream is cut into frames, each compressed as its own
/// zstd frame (several at once, on the thread pool) and written to the destination in order. <see cref="Finish"/>
/// adds the seek table and goes back to fill in the header, so the destination must be seekable.
/// </summary>
public sealed class Z3dsWriteStream : Stream
{
    private readonly Stream _dest;
    private readonly int _frameSize;
    private readonly int _level;
    private readonly byte[] _magic;
    private readonly uint _metadataSize;
    private readonly long _headerOffset;
    private readonly List<byte[]> _pending = new();
    private readonly int _batch;
    private readonly List<(int Compressed, int Decompressed)> _frames = new();
    private byte[] _current;
    private int _fill;
    private long _written;
    private long _compressedBytes;
    private bool _finished;

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
        // Several frames are compressed at once, up to about 256 MiB of input at a time.
        _batch = Math.Max(1, Math.Min(Environment.ProcessorCount * 2, 256 * 1024 * 1024 / _frameSize));
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
        // The last frame of a batch may be partly full; the length travels with it below.
        _pending.Add(_current.AsSpan(0, _fill).ToArray());
        _fill = 0;
        if (_pending.Count >= _batch) CompressPending();
    }

    private void CompressPending()
    {
        if (_pending.Count == 0) return;
        var packed = new byte[_pending.Count][];
        var level = _level;
        using (var compressors = new ThreadLocal<Compressor>(() => new Compressor(level), trackAllValues: true))
        {
            Parallel.For(0, _pending.Count, i => packed[i] = compressors.Value!.Wrap(_pending[i]).ToArray());
            foreach (var c in compressors.Values) c.Dispose();
        }
        for (int i = 0; i < packed.Length; i++)
        {
            _dest.Write(packed[i]);
            _frames.Add((packed[i].Length, _pending[i].Length));
            _compressedBytes += packed[i].Length;
        }
        _pending.Clear();
    }

    /// <summary>Compresses what's left, writes the seek table and the header. Called by Dispose if not before.</summary>
    public void Finish()
    {
        if (_finished) return;
        if (_fill > 0) QueueFrame();
        CompressPending();
        var table = SeekTable.Build(_frames);
        _dest.Write(table);
        _compressedBytes += table.Length;
        long end = _dest.Position;
        _dest.Position = _headerOffset;
        _dest.Write(Z3dsFile.BuildHeader(_magic, _metadataSize, (ulong)_compressedBytes, (ulong)_written));
        _dest.Position = end;
        _finished = true;
        ArrayPool<byte>.Shared.Return(_current);
    }

    public override void Flush() { }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_finished) Finish();
        base.Dispose(disposing);
    }
}
