using Lib3dsKit.IO;
using Lib3dsKit.Cia;
using Lib3dsKit.Keys;
using Lib3dsKit.Ncch;
using Lib3dsKit.Ncsd;

namespace Lib3dsKit.Verification;

/// <summary>One NCCH inside a file (a CCI partition, a CIA content, or the file itself).</summary>
public sealed record CtrNcchInfo(
    int Index,
    string Role,
    long Offset,
    long Size,
    ulong PartitionId,
    string ProductCode,
    bool Encrypted,
    string Crypto,
    bool CanDecrypt,
    string? MissingKey);

/// <summary>Metadata about a 3DS file, for display.</summary>
public sealed record CtrFileInfo
{
    public required string Path { get; init; }
    public required CtrFileType Type { get; init; }
    public long FileSize { get; init; }
    public ulong TitleId { get; init; }
    public string? ProductCode { get; init; }
    public string? Region { get; init; }
    public ushort TitleVersion { get; init; }
    public SmdhInfo? Titles { get; init; }
    public ulong SaveDataSize { get; init; }
    public bool Encrypted { get; init; }
    /// <summary>The file is Azahar's Z3DS (.zcci, .zcia, .zcxi, .z3dsx); <see cref="FileSize"/> is that of the file it holds.</summary>
    public bool Compressed { get; init; }
    /// <summary>CCI only: card size from the header and end of the last partition.</summary>
    public long MediaSize { get; init; }
    public long UsedSize { get; init; }
    public bool IsTrimmed => Type == CtrFileType.Cci && FileSize < MediaSize;
    public string? MediaType { get; init; }
    public IReadOnlyList<CtrNcchInfo> Ncchs { get; init; } = Array.Empty<CtrNcchInfo>();
    public IReadOnlyList<string> Notes { get; init; } = Array.Empty<string>();

    public string TitleIdHex => TitleId.ToString("X16");
}

/// <summary>Reads metadata from 3DS files without modifying them.</summary>
public static class CtrInspector
{
    /// <param name="keys">Optional; needed to read the icon/titles and save size of encrypted titles.</param>
    public static CtrFileInfo Inspect(string path, CtrKeyStore? keys = null)
    {
        using var fs = CtrFile.OpenRead(path);
        return Inspect(fs, path, keys ?? new CtrKeyStore()) with { Compressed = fs is Z3ds.Z3dsReadStream };
    }

    public static CtrFileInfo Inspect(Stream s, string path, CtrKeyStore keys)
    {
        var type = CtrFile.Detect(s);
        return type switch
        {
            CtrFileType.Cci => InspectCci(s, path, keys),
            CtrFileType.Cia => InspectCia(s, path, keys),
            CtrFileType.Cxi or CtrFileType.Cfa => InspectNcch(s, path, type, keys),
            _ => new CtrFileInfo { Path = path, Type = type, FileSize = s.Length },
        };
    }

    private static CtrFileInfo InspectCci(Stream s, string path, CtrKeyStore keys)
    {
        var ncsd = new NcsdHeader(VirtualStream.ReadBytesAt(s, 0, (int)Math.Min(NcsdHeader.HeaderAreaSize, s.Length)));
        var ncchs = new List<CtrNcchInfo>();
        var notes = new List<string>();
        SmdhInfo? smdh = null;
        ulong save = 0;
        string? product = null;
        foreach (var p in ncsd.Partitions)
        {
            if (p.Offset + p.Size > s.Length)
            {
                notes.Add($"Partition {p.Index} extends past the end of the file (truncated dump).");
                continue;
            }
            var info = DescribeNcch(new SubStream(s, p.Offset, p.Size), p.Index, NcsdPartition.IndexName(p.Index),
                p.Offset, keys, out var plain, out var header);
            if (info is null) continue;
            ncchs.Add(info);
            if (p.Index == 0)
            {
                product = info.ProductCode;
                if (plain is not null && header is not null)
                {
                    smdh = NcchContent.ReadSmdh(plain, header);
                    save = NcchContent.ReadSaveDataSize(plain, header);
                }
            }
        }
        return new CtrFileInfo
        {
            Path = path,
            Type = CtrFileType.Cci,
            FileSize = s.Length,
            TitleId = ncsd.MediaId,
            ProductCode = product,
            Region = CtrFile.RegionFromProductCode(product),
            TitleVersion = ncsd.TitleVersion,
            Titles = smdh,
            SaveDataSize = save,
            Encrypted = ncchs.Any(n => n.Encrypted),
            MediaSize = ncsd.MediaSize,
            UsedSize = ncsd.UsedSize,
            MediaType = ncsd.MediaTypeName,
            Ncchs = ncchs,
            Notes = notes,
        };
    }

    private static CtrFileInfo InspectCia(Stream s, string path, CtrKeyStore keys)
    {
        var cia = CiaFile.Read(s);
        var ncchs = new List<CtrNcchInfo>();
        var notes = new List<string>();
        SmdhInfo? smdh = null;
        ulong save = cia.Tmd.SaveDataSize;
        string? product = null;
        byte[]? titleKey = null;
        bool cbcEncrypted = cia.Contents.Any(c => c.Chunk.IsEncrypted);
        if (cbcEncrypted)
        {
            try { titleKey = cia.Ticket.DecryptTitleKey(keys); }
            catch (MissingKeyException ex) { notes.Add(ex.Message); }
        }
        foreach (var c in cia.Contents)
        {
            if (c.Chunk.IsEncrypted && titleKey is null)
            {
                ncchs.Add(new CtrNcchInfo(c.Chunk.Index, ContentRole(c.Chunk.Index), c.Offset, (long)c.Chunk.Size, 0, "",
                    true, "Title key (CIA)", false, $"common{cia.Ticket.CommonKeyIndex}"));
                continue;
            }
            var content = cia.OpenContent(s, c, keys, titleKey);
            var info = DescribeNcch(content, c.Chunk.Index, ContentRole(c.Chunk.Index), c.Offset, keys, out var plain, out var header);
            if (info is null)
            {
                notes.Add($"Content {c.Chunk.Index} is not an NCCH (DSiWare/SRL or wrong title key).");
                continue;
            }
            if (c.Chunk.IsEncrypted) info = info with { Encrypted = true, Crypto = "Title key + " + info.Crypto };
            ncchs.Add(info);
            if (c.Chunk.Index == 0)
            {
                product = info.ProductCode;
                if (plain is not null && header is not null) smdh = NcchContent.ReadSmdh(plain, header);
            }
        }
        if (smdh is null && cia.Meta.Length >= 0x400 + SmdhInfo.Size)
            smdh = SmdhInfo.Parse(cia.Meta.AsSpan(0x400, SmdhInfo.Size));
        return new CtrFileInfo
        {
            Path = path,
            Type = CtrFileType.Cia,
            FileSize = s.Length,
            TitleId = cia.TitleId,
            ProductCode = product,
            Region = CtrFile.RegionFromProductCode(product),
            TitleVersion = cia.Tmd.TitleVersion,
            Titles = smdh,
            SaveDataSize = save,
            Encrypted = ncchs.Any(n => n.Encrypted),
            Ncchs = ncchs,
            Notes = notes,
        };
    }

    private static CtrFileInfo InspectNcch(Stream s, string path, CtrFileType type, CtrKeyStore keys)
    {
        var info = DescribeNcch(s, 0, type == CtrFileType.Cxi ? "Executable (CXI)" : "Data (CFA)", 0, keys, out var plain, out var header)
            ?? throw new CtrFormatException("Not an NCCH.");
        SmdhInfo? smdh = null;
        ulong save = 0;
        if (plain is not null && header is not null)
        {
            smdh = NcchContent.ReadSmdh(plain, header);
            save = NcchContent.ReadSaveDataSize(plain, header);
        }
        return new CtrFileInfo
        {
            Path = path,
            Type = type,
            FileSize = s.Length,
            TitleId = header?.ProgramId ?? 0,
            ProductCode = info.ProductCode,
            Region = CtrFile.RegionFromProductCode(info.ProductCode),
            Titles = smdh,
            SaveDataSize = save,
            Encrypted = info.Encrypted,
            Ncchs = new[] { info },
        };
    }

    internal static string ContentRole(int index) => index switch
    {
        0 => "Main content",
        1 => "Manual",
        2 => "Download Play child",
        _ => $"Content {index}",
    };

    /// <summary>Describe an NCCH; also returns a decrypted view when keys allow (caller must not dispose the source first).</summary>
    internal static CtrNcchInfo? DescribeNcch(Stream ncch, int index, string role, long offset, CtrKeyStore keys,
        out Stream? plain, out NcchHeader? plainHeader)
    {
        plain = null;
        plainHeader = null;
        if (ncch.Length < NcchHeader.Size) return null;
        var raw = VirtualStream.ReadBytesAt(ncch, 0, NcchHeader.Size);
        if (!NcchHeader.IsNcch(raw)) return null;
        var h = new NcchHeader(raw);
        string? missing = null;
        try
        {
            var ns = new NcchStream(ncch, keys);
            plain = ns;
            plainHeader = ns.DecryptedHeader;
        }
        catch (MissingKeyException ex) { missing = ex.KeyName; }
        catch (CtrFormatException) { missing = "invalid crypto settings"; }
        return new CtrNcchInfo(index, role, offset, ncch.Length, h.PartitionId, h.ProductCode,
            !h.NoCrypto, h.CryptoDescription, missing is null, missing);
    }
}
