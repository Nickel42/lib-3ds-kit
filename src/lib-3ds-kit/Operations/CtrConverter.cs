using System.Security.Cryptography;
using Lib3dsKit.Hashing;
using Lib3dsKit.IO;
using Lib3dsKit.Cia;
using Lib3dsKit.Keys;
using Lib3dsKit.Ncch;
using Lib3dsKit.Ncsd;
using Lib3dsKit.Z3ds;

namespace Lib3dsKit.Operations;

public enum CtrOutputFormat
{
    /// <summary>NCSD card image (.3ds / .cci).</summary>
    Cci,
    /// <summary>CTR Importable Archive (.cia).</summary>
    Cia,
}

public sealed class CtrConvertOptions
{
    /// <summary>Remove NCCH encryption in the output (recommended; emulators and CFW expect it).
    /// When false, NCCH encryption is preserved and only the container changes.</summary>
    public bool Decrypt { get; init; } = true;

    /// <summary>For CCI output: write a trimmed image (ends after the last partition) instead of padding to card size.</summary>
    public bool Trim { get; init; } = true;

    /// <summary>Replace an existing output file.</summary>
    public bool Overwrite { get; init; }

    /// <summary>Hash the output (CRC32/MD5/SHA-1/SHA-256). CIA outputs need an extra read pass for this.</summary>
    public bool ComputeOutputHashes { get; init; } = true;

    /// <summary>
    /// Certificate chain for CCI→CIA and CDN→CIA. Falls back to the certificates that came with a CDN
    /// download, then <see cref="CtrKeyStore.CertificateChain"/>, then zeros.
    /// </summary>
    public byte[]? CertificateChain { get; init; }

    /// <summary>CDN→CIA: check every content against its TMD SHA-256 before writing (one extra read of the input).</summary>
    public bool VerifyContents { get; init; } = true;

    /// <summary>
    /// CDN→CIA: when the ticket's title version differs from the TMD's, write the TMD's version into the
    /// ticket. Installers ignore the mismatch; this only makes the CIA consistent.
    /// </summary>
    public bool MatchTicketVersionToTmd { get; init; }

    /// <summary>
    /// Write the result compressed in Azahar's Z3DS format (.zcci for a CCI, .zcia for a CIA, .zcxi for
    /// an NCCH). <see cref="CtrOperationResult.OutputHashes"/> are still those of the plain result.
    /// </summary>
    public bool Compress { get; init; }

    /// <summary>zstd level for <see cref="Compress"/> and <see cref="CtrConverter.Compress"/> (Azahar uses 3).</summary>
    public int CompressionLevel { get; init; } = 3;

    /// <summary>Bytes per Z3DS frame; 0 for Azahar's own (256 KiB, or 32 MiB for a CIA).</summary>
    public int CompressionFrameSize { get; init; }

    internal CtrConvertOptions With(bool compress) => new()
    {
        Decrypt = Decrypt, Trim = Trim, Overwrite = Overwrite, ComputeOutputHashes = ComputeOutputHashes,
        CertificateChain = CertificateChain, VerifyContents = VerifyContents, MatchTicketVersionToTmd = MatchTicketVersionToTmd,
        Compress = compress, CompressionLevel = CompressionLevel, CompressionFrameSize = CompressionFrameSize,
    };
}

/// <summary>Outcome of a conversion.</summary>
/// <param name="OutputHashes">Hashes of the plain result, also when it was written compressed.</param>
public sealed record CtrOperationResult(string OutputPath, CtrFileType OutputType, FileHashes? OutputHashes, IReadOnlyList<string> Warnings)
{
    /// <summary>Whether the output is compressed (Z3DS).</summary>
    public bool Compressed { get; init; }
}

/// <summary>
/// Decrypts, converts (CCI ↔ CIA), trims and untrims 3DS files. All methods stream: memory use
/// is a few MiB regardless of file size. Async methods run on the thread pool, so they are safe
/// to await from the Avalonia UI thread; pass an <see cref="IProgress{T}"/> created on the UI
/// thread (e.g. <c>new Progress&lt;OperationProgress&gt;(...)</c>) for progress updates.
/// </summary>
public sealed class CtrConverter
{
    private readonly CtrKeyStore _keys;

    public CtrConverter(CtrKeyStore keys) => _keys = keys;

    // ============================================================ public API ===

    /// <summary>Decrypt a CCI, CIA, CXI or CFA, keeping its format (a CCI stays trimmed or untrimmed as it was).</summary>
    public Task<CtrOperationResult> DecryptAsync(string input, string output, CtrConvertOptions? options = null,
        IProgress<OperationProgress>? progress = null, CancellationToken ct = default) =>
        Task.Run(() => Decrypt(input, output, options ?? new(), progress, ct), ct);

    /// <summary>Convert to another container. Same-format "conversion" decrypts (and trims for CCI) according to the options.</summary>
    public Task<CtrOperationResult> ConvertAsync(string input, string output, CtrOutputFormat target,
        CtrConvertOptions? options = null, IProgress<OperationProgress>? progress = null, CancellationToken ct = default) =>
        Task.Run(() => Convert(input, output, target, options ?? new(), progress, ct), ct);

    /// <summary>Remove the 0xFF padding after the last partition of a CCI.</summary>
    public Task<CtrOperationResult> TrimAsync(string input, string output, CtrConvertOptions? options = null,
        IProgress<OperationProgress>? progress = null, CancellationToken ct = default) =>
        Task.Run(() => Trim(input, output, options ?? new(), progress, ct), ct);

    /// <summary>
    /// Compress a CCI, CIA, CXI/CFA or 3DSX as it is into Azahar's Z3DS format (.zcci, .zcia, .zcxi, .z3dsx).
    /// Nothing is decrypted; convert or decrypt with <see cref="CtrConvertOptions.Compress"/> for that.
    /// </summary>
    public Task<CtrOperationResult> CompressAsync(string input, string output, CtrConvertOptions? options = null,
        IProgress<OperationProgress>? progress = null, CancellationToken ct = default) =>
        Task.Run(() => Compress(input, output, options ?? new(), progress, ct), ct);

    /// <summary>Decompress a Z3DS file (.zcci, .zcia, .zcxi, .z3dsx) back to the file it holds, byte for byte.</summary>
    public Task<CtrOperationResult> DecompressAsync(string input, string output, CtrConvertOptions? options = null,
        IProgress<OperationProgress>? progress = null, CancellationToken ct = default) =>
        Task.Run(() => Decompress(input, output, options ?? new(), progress, ct), ct);

    /// <summary>Pad a trimmed CCI with 0xFF back to the card size declared in its header.</summary>
    public Task<CtrOperationResult> UntrimAsync(string input, string output, CtrConvertOptions? options = null,
        IProgress<OperationProgress>? progress = null, CancellationToken ct = default) =>
        Task.Run(() => Untrim(input, output, options ?? new(), progress, ct), ct);

    // ======================================================= synchronous API ===

    public CtrOperationResult Decrypt(string input, string output, CtrConvertOptions options,
        IProgress<OperationProgress>? progress = null, CancellationToken ct = default)
    {
        if (Directory.Exists(input)) return CdnToCia(input, output, options, decrypt: true, progress, ct);
        using var src = CtrFile.OpenRead(input);
        var type = CtrFile.Detect(src);
        return type switch
        {
            CtrFileType.Cci => DecryptCci(src, output, options, progress, ct),
            CtrFileType.Cia => DecryptCia(src, output, options, progress, ct),
            CtrFileType.Cxi or CtrFileType.Cfa => DecryptNcch(src, output, type, options, progress, ct),
            CtrFileType.ThreeDsx => throw new CtrFormatException("3DSX homebrew is not encrypted."),
            _ => throw new CtrFormatException("Unrecognized file; expected .3ds/.cci, .cia, .cxi or .cfa."),
        };
    }

    public CtrOperationResult Convert(string input, string output, CtrOutputFormat target, CtrConvertOptions options,
        IProgress<OperationProgress>? progress = null, CancellationToken ct = default)
    {
        if (Directory.Exists(input))
        {
            if (target != CtrOutputFormat.Cia)
                throw new CtrFormatException("A CDN folder converts to CIA; convert that CIA to CCI afterwards.");
            return CdnToCia(input, output, options, options.Decrypt, progress, ct);
        }
        using var src = CtrFile.OpenRead(input);
        var type = CtrFile.Detect(src);
        switch (type, target)
        {
            case (CtrFileType.Cci, CtrOutputFormat.Cia):
                return CciToCia(src, output, options, progress, ct);
            case (CtrFileType.Cia, CtrOutputFormat.Cci):
                return CiaToCci(src, output, options, progress, ct);
            case (CtrFileType.Cia, CtrOutputFormat.Cia):
                if (!options.Decrypt) throw new CtrFormatException("Input is already a CIA; nothing to do.");
                return DecryptCia(src, output, options, progress, ct);
            case (CtrFileType.Cci, CtrOutputFormat.Cci):
                return CciToCci(src, output, options, progress, ct);
            case (CtrFileType.Cxi or CtrFileType.Cfa, _):
                throw new CtrFormatException("Standalone CXI/CFA files can only be decrypted, not converted.");
            default:
                throw new CtrFormatException($"Cannot convert {type} to {target}.");
        }
    }

    public CtrOperationResult Trim(string input, string output, CtrConvertOptions options,
        IProgress<OperationProgress>? progress = null, CancellationToken ct = default)
    {
        using var src = CtrFile.OpenRead(input);
        if (CtrFile.Detect(src) != CtrFileType.Cci) throw new CtrFormatException("Only CCI (.3ds) images can be trimmed.");
        var ncsd = ReadNcsd(src);
        if (src.Length < ncsd.UsedSize) throw new CtrFormatException("Image is shorter than its partitions (truncated dump).");
        return WriteSequential(output, CtrFileType.Cci, options, progress, ct, ncsd.UsedSize, (dst, tracker, hasher) =>
            StreamCopier.Copy(new SubStream(src, 0, ncsd.UsedSize), dst, ncsd.UsedSize, tracker, ct, hasher), new List<string>());
    }

    public CtrOperationResult Untrim(string input, string output, CtrConvertOptions options,
        IProgress<OperationProgress>? progress = null, CancellationToken ct = default)
    {
        using var src = CtrFile.OpenRead(input);
        if (CtrFile.Detect(src) != CtrFileType.Cci) throw new CtrFormatException("Only CCI (.3ds) images can be untrimmed.");
        var ncsd = ReadNcsd(src);
        if (src.Length > ncsd.MediaSize) throw new CtrFormatException("Image is already larger than its declared card size.");
        return WriteSequential(output, CtrFileType.Cci, options, progress, ct, ncsd.MediaSize, (dst, tracker, hasher) =>
        {
            src.Position = 0;
            StreamCopier.Copy(src, dst, src.Length, tracker, ct, hasher);
            StreamCopier.Fill(dst, ncsd.MediaSize - src.Length, 0xFF, tracker, ct, hasher);
        }, new List<string>());
    }

    public CtrOperationResult Compress(string input, string output, CtrConvertOptions options,
        IProgress<OperationProgress>? progress = null, CancellationToken ct = default)
    {
        if (CtrFile.IsCompressed(input)) throw new CtrFormatException("Input is already compressed (Z3DS).");
        using var src = CtrFile.OpenRaw(input);
        var type = CtrFile.Detect(src);
        if (type == CtrFileType.Unknown) throw new CtrFormatException("Unrecognized file; expected .3ds/.cci, .cia, .cxi, .cfa or .3dsx.");
        src.Position = 0;
        return WriteSequential(output, type, options.With(compress: true), progress, ct, src.Length, (dst, tracker, hasher) =>
            StreamCopier.CopyAll(src, dst, tracker, ct, hasher), new List<string>());
    }

    public CtrOperationResult Decompress(string input, string output, CtrConvertOptions options,
        IProgress<OperationProgress>? progress = null, CancellationToken ct = default)
    {
        if (!CtrFile.IsCompressed(input)) throw new CtrFormatException("Input isn't compressed (Z3DS).");
        using var src = CtrFile.OpenRead(input);
        var type = CtrFile.Detect(src);
        src.Position = 0;
        return WriteSequential(output, type, options.With(compress: false), progress, ct, src.Length, (dst, tracker, hasher) =>
            StreamCopier.CopyAll(src, dst, tracker, ct, hasher), new List<string>());
    }

    // ============================================================= decrypt ===

    private CtrOperationResult DecryptNcch(Stream src, string output, CtrFileType type, CtrConvertOptions options,
        IProgress<OperationProgress>? progress, CancellationToken ct)
    {
        var warnings = new List<string>();
        using var ncch = new NcchStream(src, _keys);
        if (!ncch.WasEncrypted) warnings.Add("Input was already decrypted; output is an unchanged copy.");
        return WriteSequential(output, type, options, progress, ct, src.Length, (dst, tracker, hasher) =>
            StreamCopier.CopyAll(ncch, dst, tracker, ct, hasher), warnings);
    }

    private CtrOperationResult DecryptCci(Stream src, string output, CtrConvertOptions options,
        IProgress<OperationProgress>? progress, CancellationToken ct)
    {
        var warnings = new List<string>();
        var ncsd = ReadNcsd(src);
        var view = BuildDecryptedCciView(src, ncsd, warnings);
        return WriteSequential(output, CtrFileType.Cci, options, progress, ct, view.Length, (dst, tracker, hasher) =>
            StreamCopier.CopyAll(view, dst, tracker, ct, hasher), warnings);
    }

    /// <summary>
    /// A stream equal to the CCI file with every NCCH partition decrypted. Bytes outside
    /// partitions (header area, padding) are passed through unchanged.
    /// </summary>
    internal Stream BuildDecryptedCciView(Stream src, NcsdHeader ncsd, List<string> warnings)
    {
        var pieces = new List<Stream>();
        long pos = 0;
        bool anyEncrypted = false;
        foreach (var p in ncsd.Partitions.OrderBy(p => p.Offset))
        {
            if (p.Offset < pos) throw new CtrFormatException("Overlapping NCSD partitions.");
            if (p.Offset + p.Size > src.Length)
                throw new CtrFormatException($"Partition {p.Index} extends past the end of the file (truncated dump).");
            if (p.Offset > pos) pieces.Add(new SubStream(src, pos, p.Offset - pos));
            var raw = new SubStream(src, p.Offset, p.Size);
            if (IsNcch(raw))
            {
                var ns = new NcchStream(raw, _keys);
                anyEncrypted |= ns.WasEncrypted;
                pieces.Add(ns);
            }
            else
            {
                pieces.Add(raw);
            }
            pos = p.Offset + p.Size;
        }
        if (pos < src.Length) pieces.Add(new SubStream(src, pos, src.Length - pos));
        if (!anyEncrypted) warnings.Add("Input was already decrypted; output is an unchanged copy.");
        return new ConcatStream(pieces);
    }

    private CtrOperationResult DecryptCia(Stream src, string output, CtrConvertOptions options,
        IProgress<OperationProgress>? progress, CancellationToken ct, List<string>? earlierWarnings = null)
    {
        var warnings = earlierWarnings ?? new List<string>();
        var cia = CiaFile.Read(src);
        byte[]? titleKey = cia.Contents.Any(c => c.Chunk.IsEncrypted) ? cia.Ticket.DecryptTitleKey(_keys) : null;
        var newChunks = cia.Tmd.Chunks.ToList();
        var tracker = new ProgressTracker(progress, CiaProgressTotal(src.Length, options));
        using var writer = CiaWriter(output, options);
        var dst = writer.Stream;

        tracker.SetStage("Copying CIA header");
        StreamCopier.Copy(new SubStream(src, 0, cia.TmdOffset), dst, cia.TmdOffset, tracker, ct);
        long tmdLen = cia.Tmd.Raw.Length;
        StreamCopier.Fill(dst, tmdLen, 0, tracker, ct);                 // placeholder, rewritten below
        long pos = cia.TmdOffset + tmdLen;
        StreamCopier.Copy(new SubStream(src, pos, cia.ContentOffset - pos), dst, cia.ContentOffset - pos, tracker, ct);
        pos = cia.ContentOffset;

        bool changed = false;
        foreach (var content in cia.Contents)
        {
            ct.ThrowIfCancellationRequested();
            if (content.Offset > pos)
                StreamCopier.Copy(new SubStream(src, pos, content.Offset - pos), dst, content.Offset - pos, tracker, ct);
            tracker.SetStage($"Decrypting content {content.Chunk.Index}");
            var plainCbc = cia.OpenContent(src, content, _keys, titleKey);
            Stream data = plainCbc;
            if (IsNcch(plainCbc))
            {
                var ns = new NcchStream(plainCbc, _keys);
                changed |= ns.WasEncrypted;
                data = ns;
            }
            changed |= content.Chunk.IsEncrypted;
            using var sha = new MultiHasher(HashKinds.Sha256);
            StreamCopier.CopyAll(data, dst, tracker, ct, sha);
            if (!ReferenceEquals(data, plainCbc)) data.Dispose();   // NcchStream owns two Aes instances, not the inner stream
            int i = newChunks.IndexOf(content.Chunk);
            newChunks[i] = content.Chunk with
            {
                Type = (ushort)(content.Chunk.Type & ~ContentChunk.TypeEncrypted),
                Hash = System.Convert.FromHexString(sha.Finish().Sha256!),
            };
            pos = content.Offset + (long)content.Chunk.Size;
        }
        if (pos < src.Length) StreamCopier.Copy(new SubStream(src, pos, src.Length - pos), dst, src.Length - pos, tracker, ct);
        if (!changed) warnings.Add("Input was already decrypted; output is an unchanged copy.");

        dst.Position = cia.TmdOffset;
        dst.Write(cia.Tmd.Rebuild(newChunks));
        return Finish(writer, output, CtrFileType.Cia, options, warnings, tracker, ct);
    }

    // =========================================================== CDN → CIA ===

    /// <summary>
    /// Builds a CIA from a CDN download. The folder is laid out as a CIA in memory (archive header,
    /// certificate chain, ticket, TMD, then the content files back to back) and that stream goes
    /// through the normal CIA path: decrypted like any CIA, or copied as-is when encryption is kept.
    /// </summary>
    private CtrOperationResult CdnToCia(string folder, string output, CtrConvertOptions options, bool decrypt,
        IProgress<OperationProgress>? progress, CancellationToken ct)
    {
        var cdn = CdnTitle.Open(folder);
        var warnings = new List<string>(cdn.Warnings);
        if (cdn.TicketVersionMismatch)
            warnings.Add(options.MatchTicketVersionToTmd
                ? $"Ticket title version ({cdn.Ticket.TitleVersion}) differed from the TMD ({cdn.Tmd.TitleVersion}); wrote {cdn.Tmd.TitleVersion} into the ticket."
                : $"Ticket title version ({cdn.Ticket.TitleVersion}) does not match the TMD ({cdn.Tmd.TitleVersion}). "
                  + "Installers ignore this; MatchTicketVersionToTmd (--match-ticket-version) writes a matching ticket.");
        if (cdn.Missing.Count > 0)
        {
            string ids = string.Join(", ", cdn.Missing.Select(c => c.Id.ToString("x8")));
            if (!cdn.IsDlc)
                throw new CtrFormatException($"The CDN folder is missing content(s) {ids} listed in the TMD.");
            warnings.Add($"DLC contents not in the folder were left out: {ids}.");
        }

        byte[]? chain = options.CertificateChain ?? cdn.BuildCertificateChain() ?? _keys.CertificateChain;
        if (chain is null)
        {
            chain = new byte[CiaBuilder.DefaultCertChainSize];
            warnings.Add("No certificate chain in the CDN folder or loaded; wrote a zero-filled one. Emulators accept this; for console installs load certificates from any CIA you own.");
        }
        byte[] ticket = cdn.TicketBytes(options.MatchTicketVersionToTmd);
        byte[] tmd = cdn.Tmd.Raw;
        ulong contentSize = (ulong)cdn.Contents.Sum(c => (long)c.Chunk.Size);
        byte[] header = CiaBuilder.BuildArchiveHeader(chain.Length, ticket.Length, tmd.Length, 0, contentSize,
            cdn.Contents.Select(c => (int)c.Chunk.Index));

        var files = new List<FileStream>();
        try
        {
            var pieces = new List<Stream>();
            long pos = 0;
            void Add(byte[] bytes, bool pad)
            {
                pieces.Add(new MemoryStream(bytes, writable: false));
                pos += bytes.Length;
                if (!pad) return;
                long padding = CiaFile.Align(pos) - pos;
                if (padding > 0) pieces.Add(new MemoryStream(new byte[padding], writable: false));
                pos += padding;
            }
            Add(header, pad: true);
            Add(chain, pad: true);
            Add(ticket, pad: true);
            Add(tmd, pad: true);
            foreach (var c in cdn.Contents)
            {
                var fs = CtrFile.OpenRaw(c.Path);
                files.Add(fs);
                pieces.Add(new SubStream(fs, 0, (long)c.Chunk.Size));
            }
            using var cia = new ConcatStream(pieces);

            long verifyBytes = options.VerifyContents ? (long)contentSize : 0;
            long writeTotal = CiaProgressTotal(cia.Length, options);
            if (options.VerifyContents)
                VerifyCdnContents(cdn, files, writeTotal, warnings, progress, ct);
            var mapped = verifyBytes > 0 && progress is not null ? new OffsetProgress(progress, verifyBytes) : progress;

            if (decrypt) return DecryptCia(cia, output, options, mapped, ct, warnings);

            var tracker = new ProgressTracker(mapped, writeTotal);
            using var writer = new AtomicFileWriter(output, options.Overwrite);
            tracker.SetStage("Writing " + Path.GetFileName(output));
            StreamCopier.CopyAll(cia, writer.Stream, tracker, ct);
            return Finish(writer, output, CtrFileType.Cia, options, warnings, tracker, ct);
        }
        finally
        {
            foreach (var f in files) f.Dispose();
        }
    }

    /// <summary>
    /// Hashes each content with its title-key layer removed and compares it with the TMD, so a damaged
    /// or incomplete download is caught before anything is written.
    /// </summary>
    private void VerifyCdnContents(CdnTitle cdn, IReadOnlyList<FileStream> files, long laterBytes, List<string> warnings,
        IProgress<OperationProgress>? progress, CancellationToken ct)
    {
        byte[]? titleKey = null;
        if (cdn.Contents.Any(c => c.Chunk.IsEncrypted))
        {
            try
            {
                titleKey = cdn.Ticket.DecryptTitleKey(_keys);
            }
            catch (MissingKeyException ex)
            {
                warnings.Add($"Contents were not verified: {ex.Message}");
                return;
            }
        }

        long total = cdn.Contents.Sum(c => (long)c.Chunk.Size);
        var tracker = new ProgressTracker(progress, total + laterBytes);
        for (int i = 0; i < cdn.Contents.Count; i++)
        {
            var chunk = cdn.Contents[i].Chunk;
            tracker.SetStage($"Verifying content {chunk.Index}");
            Stream data = new SubStream(files[i], 0, (long)chunk.Size);
            if (chunk.IsEncrypted)
            {
                var iv = new byte[16];
                System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(iv, chunk.Index);
                data = new Lib3dsKit.Crypto.AesCbcDecryptStream(data, titleKey!, iv);
            }
            using var sha = new MultiHasher(HashKinds.Sha256);
            StreamCopier.CopyAll(data, null, tracker, ct, sha);
            if (!System.Convert.FromHexString(sha.Finish().Sha256!).AsSpan().SequenceEqual(chunk.Hash))
                throw new CtrFormatException($"Content {chunk.Id:x8} does not match its TMD hash (damaged download or wrong title key).");
        }
    }

    /// <summary>Shifts a later step's progress past bytes already reported, so one bar covers both steps.</summary>
    private sealed class OffsetProgress(IProgress<OperationProgress> inner, long offset) : IProgress<OperationProgress>
    {
        public void Report(OperationProgress value) =>
            inner.Report(value with { BytesProcessed = value.BytesProcessed + offset, TotalBytes = value.TotalBytes + offset });
    }

    // =========================================================== CCI → CCI ===

    private CtrOperationResult CciToCci(Stream src, string output, CtrConvertOptions options,
        IProgress<OperationProgress>? progress, CancellationToken ct)
    {
        var warnings = new List<string>();
        var ncsd = ReadNcsd(src);
        Stream view = options.Decrypt ? BuildDecryptedCciView(src, ncsd, warnings) : src;
        long len = options.Trim ? ncsd.UsedSize : Math.Max(ncsd.MediaSize, view.Length);
        long copy = Math.Min(len, view.Length);
        return WriteSequential(output, CtrFileType.Cci, options, progress, ct, len, (dst, tracker, hasher) =>
        {
            view.Position = 0;
            StreamCopier.Copy(view, dst, copy, tracker, ct, hasher);
            StreamCopier.Fill(dst, len - copy, 0xFF, tracker, ct, hasher);
        }, warnings);
    }

    // =========================================================== CCI → CIA ===

    private CtrOperationResult CciToCia(Stream src, string output, CtrConvertOptions options,
        IProgress<OperationProgress>? progress, CancellationToken ct)
    {
        var warnings = new List<string>();
        var ncsd = ReadNcsd(src);
        var contents = new List<(int Index, Stream Data)>();
        PreparedContent? first = null;
        foreach (var p in ncsd.Partitions.OrderBy(p => p.Index))
        {
            if (p.Index > 5)
            {
                warnings.Add($"Skipped partition {p.Index} ({NcsdPartition.IndexName(p.Index)}); system update data does not belong in a CIA.");
                continue;
            }
            if (p.Offset + p.Size > src.Length)
                throw new CtrFormatException($"Partition {p.Index} extends past the end of the file (truncated dump).");
            var prepared = PrepareContent(new SubStream(src, p.Offset, p.Size), p.Index, options.Decrypt, sdFlag: true, warnings);
            if (p.Index == 0) first = prepared;
            contents.Add((p.Index, prepared.Output));
        }
        if (contents.Count == 0 || contents[0].Index != 0) throw new CtrFormatException("CCI has no game partition (partition 0).");

        ulong titleId = ncsd.MediaId;
        ushort titleVersion = ncsd.TitleVersion;
        ulong saveSize = first?.PlainView is { } pv0 ? NcchContent.ReadSaveDataSize(pv0, first.PlainHeader!) : 0;
        byte[] meta = first?.PlainView is { } pv
            ? CiaBuilder.BuildMeta(NcchContent.ReadExHeader(pv, first.PlainHeader!), NcchContent.ReadExeFsFile(pv, first.PlainHeader!, "icon"))
            : Array.Empty<byte>();
        if (meta.Length == 0) warnings.Add("No meta section written (icon/extended header unavailable).");

        byte[] cert = options.CertificateChain ?? _keys.CertificateChain ?? new byte[CiaBuilder.DefaultCertChainSize];
        if (options.CertificateChain is null && _keys.CertificateChain is null)
            warnings.Add("No certificate chain loaded; wrote a zero-filled one. Emulators accept this; for console installs load certificates from any CIA you own.");

        byte[] ticket = CiaBuilder.BuildTicket(titleId, titleVersion);
        int tmdSize = CiaBuilder.TmdSize(contents.Count);
        ulong contentSize = (ulong)contents.Sum(c => c.Data.Length);
        byte[] header = CiaBuilder.BuildArchiveHeader(cert.Length, ticket.Length, tmdSize, meta.Length, contentSize,
            contents.Select(c => c.Index));

        var tracker = new ProgressTracker(progress, CiaProgressTotal((long)contentSize, options));
        using var writer = CiaWriter(output, options);
        var dst = writer.Stream;
        dst.Write(header);
        StreamCopier.PadTo(dst, CiaFile.Alignment);
        dst.Write(cert);
        StreamCopier.PadTo(dst, CiaFile.Alignment);
        dst.Write(ticket);
        StreamCopier.PadTo(dst, CiaFile.Alignment);
        long tmdOffset = dst.Position;
        dst.Write(new byte[tmdSize]);
        StreamCopier.PadTo(dst, CiaFile.Alignment);

        var chunks = new List<ContentChunk>();
        foreach (var (index, data) in contents)
        {
            tracker.SetStage($"Writing content {index}");
            using var sha = new MultiHasher(HashKinds.Sha256);
            StreamCopier.CopyAll(data, dst, tracker, ct, sha);
            chunks.Add(new ContentChunk((uint)index, (ushort)index, 0, (ulong)data.Length,
                System.Convert.FromHexString(sha.Finish().Sha256!)));
        }
        if (meta.Length > 0)
        {
            StreamCopier.PadTo(dst, CiaFile.Alignment);
            dst.Write(meta);
        }
        dst.Position = tmdOffset;
        dst.Write(CiaBuilder.BuildTmd(titleId, titleVersion, (uint)saveSize, chunks));
        return Finish(writer, output, CtrFileType.Cia, options, warnings, tracker, ct);
    }

    // =========================================================== CIA → CCI ===

    private CtrOperationResult CiaToCci(Stream src, string output, CtrConvertOptions options,
        IProgress<OperationProgress>? progress, CancellationToken ct)
    {
        var warnings = new List<string>();
        var cia = CiaFile.Read(src);
        ulong tid = cia.TitleId;
        uint high = (uint)(tid >> 32);
        if (high != 0x00040000 && high != 0x00040002)
            throw new CtrFormatException($"Title {tid:X16} is not a game application (updates, DLC and system titles cannot become a CCI).");
        byte[]? titleKey = cia.Contents.Any(c => c.Chunk.IsEncrypted) ? cia.Ticket.DecryptTitleKey(_keys) : null;

        var parts = new List<(int Index, Stream Data)>();
        PreparedContent? first = null;
        foreach (var content in cia.Contents.OrderBy(c => c.Chunk.Index))
        {
            if (content.Chunk.Index > 7)
                throw new CtrFormatException($"Content index {content.Chunk.Index} cannot be placed in a CCI (max 7).");
            var plainCbc = cia.OpenContent(src, content, _keys, titleKey);
            if (!IsNcch(plainCbc)) throw new CtrFormatException($"Content {content.Chunk.Index} is not an NCCH (wrong title key?).");
            var prepared = PrepareContent(plainCbc, content.Chunk.Index, options.Decrypt, sdFlag: false, warnings);
            if (content.Chunk.Index == 0) first = prepared;
            long padded = (prepared.Output.Length + NcsdHeader.MediaUnit - 1) / NcsdHeader.MediaUnit * NcsdHeader.MediaUnit;
            Stream data = padded == prepared.Output.Length
                ? prepared.Output
                : new ConcatStream(new[] { prepared.Output, new FillStream(padded - prepared.Output.Length, 0xFF) });
            parts.Add((content.Chunk.Index, data));
        }
        if (first is null) throw new CtrFormatException("CIA has no content 0 (game executable).");

        ulong saveSize = first.PlainView is { } pv ? NcchContent.ReadSaveDataSize(pv, first.PlainHeader!) : 0;
        var headerParts = parts.Select(p => (p.Index, p.Data.Length, VirtualStream.ReadBytesAt(p.Data, 0, 0x200))).ToList();
        byte[] ncsd = NcsdBuilder.Build(tid, cia.Tmd.TitleVersion, headerParts, saveSize);
        long used = ncsd.Length + parts.Sum(p => p.Data.Length);
        long total = options.Trim ? used : NcsdBuilder.CardSizeFor(used);
        return WriteSequential(output, CtrFileType.Cci, options, progress, ct, total, (dst, tracker, hasher) =>
        {
            dst.Write(ncsd);
            hasher?.Append(ncsd);
            tracker.Advance(ncsd.Length);
            foreach (var (index, data) in parts)
            {
                tracker.SetStage($"Writing partition {index}");
                StreamCopier.CopyAll(data, dst, tracker, ct, hasher);
            }
            StreamCopier.Fill(dst, total - used, 0xFF, tracker, ct, hasher);
        }, warnings);
    }

    // ============================================================= helpers ===

    /// <summary>An NCCH prepared for writing into another container.</summary>
    internal sealed record PreparedContent(Stream Output, Stream? PlainView, NcchHeader? PlainHeader);

    /// <summary>
    /// Decrypt (optionally) and patch the extended header's "SD application" flag of content 0:
    /// set for CIA (installed to SD), cleared for CCI (game card). When encryption is kept, the
    /// flag is patched by XOR-ing the plaintext delta into the AES-CTR ciphertext.
    /// </summary>
    internal PreparedContent PrepareContent(Stream raw, int index, bool decrypt, bool? sdFlag, List<string> warnings)
    {
        if (!IsNcch(raw)) return new PreparedContent(raw, null, null);
        NcchStream? ns = null;
        try
        {
            ns = new NcchStream(raw, _keys);
        }
        catch (MissingKeyException ex) when (!decrypt)
        {
            warnings.Add($"Content {index}: {ex.Message} Kept as-is; extended header and meta not updated.");
        }
        if (ns is null) return new PreparedContent(raw, null, null);

        var plainHeader = ns.DecryptedHeader;
        Stream output = decrypt ? ns : raw;
        Stream plainView = ns;
        if (index == 0 && sdFlag is bool sd && plainHeader.HasExHeader && plainHeader.IsExecutable)
        {
            byte[] exh = ns.ReadDecrypted(0x200, 0x400);
            byte oldFlag = exh[0x0D];
            byte newFlag = sd ? (byte)(oldFlag | 0x02) : (byte)(oldFlag & ~0x02);
            if (newFlag != oldFlag)
            {
                exh[0x0D] = newFlag;
                byte[] hash = SHA256.HashData(exh);
                var patchedPlain = new OverlayStream(ns).Replace(0x20D, new[] { newFlag }).Replace(0x160, hash);
                plainView = patchedPlain;
                if (decrypt)
                {
                    output = patchedPlain;
                }
                else
                {
                    var o = new OverlayStream(raw).Replace(0x160, hash);
                    if (ns.WasEncrypted) o.Xor(0x20D, new[] { (byte)(oldFlag ^ newFlag) });
                    else o.Replace(0x20D, new[] { newFlag });
                    output = o;
                }
                plainHeader = new NcchHeader(VirtualStream.ReadBytesAt(plainView, 0, NcchHeader.Size));
            }
        }
        return new PreparedContent(output, plainView, plainHeader);
    }

    private static bool IsNcch(Stream s)
    {
        if (s.Length < NcchHeader.Size) return false;
        var magic = VirtualStream.ReadBytesAt(s, 0x100, 4);
        return magic[0] == 'N' && magic[1] == 'C' && magic[2] == 'C' && magic[3] == 'H';
    }

    private static NcsdHeader ReadNcsd(Stream s) =>
        new(VirtualStream.ReadBytesAt(s, 0, (int)Math.Min(NcsdHeader.HeaderAreaSize, s.Length)));

    private delegate void SequentialWriter(Stream destination, ProgressTracker tracker, MultiHasher? hasher);

    private static CtrOperationResult WriteSequential(string output, CtrFileType type, CtrConvertOptions options,
        IProgress<OperationProgress>? progress, CancellationToken ct, long totalBytes, SequentialWriter write, List<string> warnings)
    {
        var tracker = new ProgressTracker(progress, totalBytes);
        using var hasher = options.ComputeOutputHashes ? new MultiHasher() : null;
        using var writer = new AtomicFileWriter(output, options.Overwrite);
        tracker.SetStage((options.Compress ? "Compressing " : "Writing ") + Path.GetFileName(output));
        if (options.Compress)
        {
            using var z = new Z3dsWriteStream(writer.Stream, type, options.CompressionFrameSize, options.CompressionLevel);
            write(z, tracker, hasher);
            ct.ThrowIfCancellationRequested();
            z.Finish();
        }
        else write(writer.Stream, tracker, hasher);
        ct.ThrowIfCancellationRequested();
        writer.Commit();
        return new CtrOperationResult(Path.GetFullPath(output), type, hasher?.Finish(), warnings) { Compressed = options.Compress };
    }

    /// <summary>
    /// Where a CIA is written: the output itself, or, when it's to be compressed, a plain file beside it
    /// that <see cref="Finish"/> compresses (a CIA's TMD is filled in last, so it can't be compressed as it's written).
    /// </summary>
    private static AtomicFileWriter CiaWriter(string output, CtrConvertOptions options)
    {
        if (!options.Compress) return new AtomicFileWriter(output, options.Overwrite);
        if (!options.Overwrite && File.Exists(output)) throw new IOException($"Output file already exists: {Path.GetFullPath(output)}");
        return new AtomicFileWriter(output + ".plain", overwrite: true);
    }

    /// <summary>Progress total for a CIA write: the bytes written, plus a read-back pass when output hashes are wanted.</summary>
    private static long CiaProgressTotal(long writeBytes, CtrConvertOptions options) =>
        options.ComputeOutputHashes ? writeBytes * 2 : writeBytes;

    private static CtrOperationResult Finish(AtomicFileWriter writer, string output, CtrFileType type,
        CtrConvertOptions options, List<string> warnings, ProgressTracker tracker, CancellationToken ct)
    {
        FileHashes? hashes = null;
        if (options.ComputeOutputHashes)
        {
            // The read-back pass is part of the progress total, so the bar keeps moving instead of
            // sitting at 100% while a large CIA is hashed. Count the header/metadata bytes written
            // outside the tracked copies first, then settle the total on the real output size;
            // that keeps the fraction from stepping backwards.
            long written = writer.Stream.Length;
            if (tracker.Processed < written) tracker.Advance(written - tracker.Processed);
            tracker.TotalBytes = tracker.Processed + written;
            tracker.SetStage("Hashing " + Path.GetFileName(output));
            hashes = MultiHasher.HashStream(writer.Stream, HashKinds.All, ct, tracker);
        }
        ct.ThrowIfCancellationRequested();
        if (options.Compress)
        {
            // The plain CIA (see CiaWriter) goes into the real output compressed; its temp file is then deleted.
            var plain = writer.Stream;
            tracker.TotalBytes = tracker.Processed + plain.Length;
            tracker.SetStage("Compressing " + Path.GetFileName(output));
            using var final = new AtomicFileWriter(output, options.Overwrite);
            using (var z = new Z3dsWriteStream(final.Stream, type, options.CompressionFrameSize, options.CompressionLevel))
            {
                plain.Position = 0;
                StreamCopier.CopyAll(plain, z, tracker, ct);
                ct.ThrowIfCancellationRequested();
                z.Finish();
            }
            final.Commit();
            return new CtrOperationResult(Path.GetFullPath(output), type, hashes, warnings) { Compressed = true };
        }
        writer.Commit();
        return new CtrOperationResult(Path.GetFullPath(output), type, hashes, warnings);
    }
}
