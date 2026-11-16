using System.Security.Cryptography;
using Lib3dsKit.Hashing;
using Lib3dsKit.IO;
using Lib3dsKit.Cia;
using Lib3dsKit.Keys;
using Lib3dsKit.Ncch;
using Lib3dsKit.Ncsd;
using Lib3dsKit.Z3ds;

namespace Lib3dsKit.Verification;

public sealed class CtrVerifyOptions
{
    /// <summary>Check the hashes stored inside the file (TMD content hashes, NCCH header hashes).</summary>
    public bool CheckIntegrity { get; init; } = true;
    public HashKinds HashKinds { get; init; } = HashKinds.All;
}

/// <summary>Overall verdict, from best to worst.</summary>
public enum CtrVerdict
{
    /// <summary>Every internal hash checked out.</summary>
    Intact,
    /// <summary>Internal checks were skipped (e.g. keys missing) or none apply.</summary>
    Unknown,
    /// <summary>An internal hash is wrong: the file is corrupt or modified.</summary>
    Bad,
}

public sealed record CtrVerifyReport
{
    public required CtrFileInfo Info { get; init; }
    /// <summary>CRC32, MD5, SHA-1 and SHA-256 of the whole file.</summary>
    public required FileHashes Hashes { get; init; }
    public IReadOnlyList<IntegrityCheck> Checks { get; init; } = Array.Empty<IntegrityCheck>();
    public CtrVerdict Verdict { get; init; }

    public bool AnyCheckFailed => Checks.Any(c => c.Status == CheckStatus.Fail);
}

/// <summary>
/// Hashes 3DS files and checks the hashes stored inside them (TMD content hashes, NCCH
/// extended header, logo, ExeFS and RomFS superblock), so you can tell whether a decrypted
/// or converted file came out intact.
/// </summary>
public sealed class CtrVerifier
{
    private readonly CtrKeyStore _keys;

    public CtrVerifier(CtrKeyStore keys) => _keys = keys;

    public Task<CtrVerifyReport> VerifyAsync(string path, CtrVerifyOptions? options = null,
        IProgress<OperationProgress>? progress = null, CancellationToken ct = default) =>
        Task.Run(() => Verify(path, options ?? new(), progress, ct), ct);

    public CtrVerifyReport Verify(string path, CtrVerifyOptions options, IProgress<OperationProgress>? progress = null,
        CancellationToken ct = default)
    {
        using var fs = CtrFile.OpenRead(path);
        var info = CtrInspector.Inspect(fs, path, _keys);

        // ---- whole-file hashes (one pass). With no hashes asked for, a plain file isn't read at all:
        // the internal checks below only read headers. A compressed file is still read through, since
        // decompressing every frame is the only way to tell a damaged frame.
        var tracker = new ProgressTracker(progress, fs.Length);
        FileHashes hashes;
        if (options.HashKinds == HashKinds.None && fs is not Z3dsReadStream)
        {
            hashes = new FileHashes(fs.Length, null, null, null, null);
        }
        else
        {
            tracker.SetStage("Hashing " + Path.GetFileName(path));
            using var raw = new MultiHasher(options.HashKinds);
            fs.Position = 0;
            StreamCopier.Copy(fs, null, fs.Length, tracker, ct, raw);
            hashes = raw.Finish();
        }

        // ---- internal integrity
        var checks = new List<IntegrityCheck>();
        if (options.CheckIntegrity)
        {
            tracker.SetStage("Checking internal hashes");
            fs.Position = 0;
            switch (info.Type)
            {
                case CtrFileType.Cci: CheckCci(fs, checks, ct); break;
                case CtrFileType.Cia: CheckCia(fs, checks, ct); break;
                case CtrFileType.Cxi or CtrFileType.Cfa: CheckNcch(fs, "", checks); break;
            }
        }

        CtrVerdict verdict;
        if (checks.Any(c => c.Status == CheckStatus.Fail)) verdict = CtrVerdict.Bad;
        else if (checks.Count > 0 && checks.All(c => c.Status == CheckStatus.Pass)) verdict = CtrVerdict.Intact;
        else verdict = CtrVerdict.Unknown;

        return new CtrVerifyReport
        {
            Info = info,
            Hashes = hashes,
            Checks = checks,
            Verdict = verdict,
        };
    }

    private void CheckNcch(Stream ncch, string prefix, List<IntegrityCheck> checks)
    {
        NcchStream ns;
        try { ns = new NcchStream(ncch, _keys); }
        catch (MissingKeyException ex)
        {
            checks.Add(new IntegrityCheck(prefix + "NCCH hashes", CheckStatus.Skipped, ex.Message));
            return;
        }
        catch (CtrFormatException ex)
        {
            checks.Add(new IntegrityCheck(prefix + "NCCH crypto", CheckStatus.Fail, ex.Message));
            return;
        }
        using (ns) checks.AddRange(NcchContent.Verify(ns, ns.DecryptedHeader, prefix));
    }

    private void CheckCci(Stream fs, List<IntegrityCheck> checks, CancellationToken ct)
    {
        var ncsd = new NcsdHeader(VirtualStream.ReadBytesAt(fs, 0, (int)Math.Min(NcsdHeader.HeaderAreaSize, fs.Length)));
        foreach (var p in ncsd.Partitions)
        {
            ct.ThrowIfCancellationRequested();
            string prefix = $"Partition {p.Index}: ";
            if (p.Offset + p.Size > fs.Length)
            {
                checks.Add(new IntegrityCheck(prefix + "present", CheckStatus.Fail, "extends past end of file"));
                continue;
            }
            var sub = new SubStream(fs, p.Offset, p.Size);
            if (!NcchHeader.IsNcch(VirtualStream.ReadBytesAt(sub, 0, (int)Math.Min(0x200, sub.Length))))
            {
                checks.Add(new IntegrityCheck(prefix + "NCCH header", CheckStatus.Fail, "missing NCCH magic"));
                continue;
            }
            CheckNcch(sub, prefix, checks);
        }
    }

    private void CheckCia(Stream fs, List<IntegrityCheck> checks, CancellationToken ct)
    {
        var cia = CiaFile.Read(fs);
        byte[]? titleKey = null;
        if (cia.Contents.Any(c => c.Chunk.IsEncrypted))
        {
            try { titleKey = cia.Ticket.DecryptTitleKey(_keys); }
            catch (MissingKeyException ex)
            {
                checks.Add(new IntegrityCheck("TMD content hashes", CheckStatus.Skipped, ex.Message));
                return;
            }
        }
        foreach (var c in cia.Contents)
        {
            ct.ThrowIfCancellationRequested();
            string prefix = $"Content {c.Chunk.Index}: ";
            var data = cia.OpenContent(fs, c, _keys, titleKey);
            using var sha = new MultiHasher(HashKinds.Sha256);
            StreamCopier.CopyAll(data, null, null, ct, sha);
            bool ok = string.Equals(sha.Finish().Sha256, MultiHasher.Hex(c.Chunk.Hash), StringComparison.Ordinal);
            checks.Add(new IntegrityCheck(prefix + "TMD SHA-256", ok ? CheckStatus.Pass : CheckStatus.Fail,
                ok ? null : "content does not match its TMD hash"));
            if (ok && data.Length >= 0x200 && NcchHeader.IsNcch(VirtualStream.ReadBytesAt(data, 0, 0x200)))
                CheckNcch(data, prefix, checks);
        }
    }
}
