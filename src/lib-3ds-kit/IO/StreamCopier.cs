using System.Buffers;
using Lib3dsKit.Hashing;

namespace Lib3dsKit.IO;

/// <summary>Progress snapshot for long-running format operations.</summary>
/// <param name="Stage">Short human-readable description of the current step.</param>
/// <param name="BytesProcessed">Bytes processed so far across the whole operation.</param>
/// <param name="TotalBytes">Total bytes the operation expects to process (0 when unknown).</param>
public readonly record struct OperationProgress(string Stage, long BytesProcessed, long TotalBytes)
{
    public double Fraction => TotalBytes <= 0 ? 0 : Math.Clamp((double)BytesProcessed / TotalBytes, 0, 1);
}

/// <summary>
/// Accumulates progress over several copy steps and throttles reports
/// (UI thread marshalling is the caller's IProgress implementation's job).
/// </summary>
public sealed class ProgressTracker
{
    private readonly IProgress<OperationProgress>? _progress;
    private long _lastReported = -1;
    private const long ReportEvery = 8L * 1024 * 1024;

    public ProgressTracker(IProgress<OperationProgress>? progress, long totalBytes)
    {
        _progress = progress;
        TotalBytes = totalBytes;
    }

    public long TotalBytes { get; set; }
    public long Processed { get; private set; }
    public string Stage { get; set; } = "";

    public void Advance(long bytes)
    {
        Processed += bytes;
        if (_progress is null) return;
        if (_lastReported < 0 || Processed - _lastReported >= ReportEvery || Processed >= TotalBytes)
        {
            _lastReported = Processed;
            _progress.Report(new OperationProgress(Stage, Processed, TotalBytes));
        }
    }

    public void SetStage(string stage)
    {
        Stage = stage;
        _progress?.Report(new OperationProgress(stage, Processed, TotalBytes));
    }
}

public static class StreamCopier
{
    public const int DefaultBufferSize = 4 * 1024 * 1024;

    /// <summary>
    /// Copy exactly <paramref name="count"/> bytes from the current position of
    /// <paramref name="source"/> to <paramref name="destination"/> (destination may be null
    /// to only hash), feeding every byte to the optional hashers.
    /// </summary>
    public static void Copy(Stream source, Stream? destination, long count,
        ProgressTracker? progress = null, CancellationToken ct = default, params MultiHasher?[] hashers)
    {
        byte[] buf = ArrayPool<byte>.Shared.Rent((int)Math.Min(DefaultBufferSize, Math.Max(count, 1)));
        try
        {
            long left = count;
            while (left > 0)
            {
                ct.ThrowIfCancellationRequested();
                int want = (int)Math.Min(buf.Length, left);
                int got = 0;
                while (got < want)
                {
                    int n = source.Read(buf, got, want - got);
                    if (n == 0) throw new EndOfStreamException($"Source ended {left - got} bytes early.");
                    got += n;
                }
                var span = buf.AsSpan(0, got);
                destination?.Write(span);
                foreach (var h in hashers) h?.Append(span);
                left -= got;
                progress?.Advance(got);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    /// <summary>Copy an entire seekable stream from position 0.</summary>
    public static void CopyAll(Stream source, Stream? destination, ProgressTracker? progress = null,
        CancellationToken ct = default, params MultiHasher?[] hashers)
    {
        source.Position = 0;
        Copy(source, destination, source.Length, progress, ct, hashers);
    }

    /// <summary>Feed <paramref name="count"/> copies of <paramref name="value"/> to the destination and hashers.</summary>
    public static void Fill(Stream? destination, long count, byte value, ProgressTracker? progress = null,
        CancellationToken ct = default, params MultiHasher?[] hashers)
    {
        if (count <= 0) return;
        byte[] buf = ArrayPool<byte>.Shared.Rent((int)Math.Min(DefaultBufferSize, count));
        try
        {
            buf.AsSpan().Fill(value);
            long left = count;
            while (left > 0)
            {
                ct.ThrowIfCancellationRequested();
                int n = (int)Math.Min(buf.Length, left);
                var span = buf.AsSpan(0, n);
                destination?.Write(span);
                foreach (var h in hashers) h?.Append(span);
                left -= n;
                progress?.Advance(n);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    /// <summary>Write zero bytes until the destination position is a multiple of <paramref name="alignment"/>.</summary>
    public static void PadTo(Stream destination, long alignment, byte value = 0)
    {
        long pad = (alignment - destination.Position % alignment) % alignment;
        if (pad > 0) Fill(destination, pad, value);
    }
}

/// <summary>
/// Writes to <c>path.tmp</c> and atomically moves it into place on <see cref="Commit"/>;
/// the temp file is deleted if the operation fails or is cancelled.
/// </summary>
public sealed class AtomicFileWriter : IDisposable
{
    private readonly string _finalPath;
    private readonly string _tempPath;
    private bool _committed;

    public AtomicFileWriter(string path, bool overwrite) : this(path, overwrite, 0) { }

    /// <param name="preallocationSize">The expected size, so the file system can set the space aside at
    /// once (0 for none). It doesn't change the file's length, which is what's written.</param>
    public AtomicFileWriter(string path, bool overwrite, long preallocationSize)
    {
        _finalPath = Path.GetFullPath(path);
        if (!overwrite && File.Exists(_finalPath))
            throw new IOException($"Output file already exists: {_finalPath}");
        var dir = Path.GetDirectoryName(_finalPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        _tempPath = _finalPath + ".lib-3ds-kit.tmp";
        Stream = new FileStream(_tempPath, new FileStreamOptions
        {
            Mode = FileMode.Create,
            Access = FileAccess.ReadWrite,
            Share = FileShare.None,
            BufferSize = 1024 * 1024,
            Options = FileOptions.None,
            PreallocationSize = Math.Max(0, preallocationSize),
        });
    }

    public FileStream Stream { get; }

    public void Commit()
    {
        Stream.Flush(true);
        Stream.Dispose();
        File.Move(_tempPath, _finalPath, overwrite: true);
        _committed = true;
    }

    public void Dispose()
    {
        if (_committed) return;
        Stream.Dispose();
        try { File.Delete(_tempPath); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
