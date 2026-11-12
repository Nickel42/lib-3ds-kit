using Lib3dsKit.IO;
using Lib3dsKit.Cia;
using Lib3dsKit.Ncch;
using Lib3dsKit.Ncsd;
using Lib3dsKit.Z3ds;

namespace Lib3dsKit;

public enum CtrFileType
{
    Unknown,
    /// <summary>NCSD card image (.3ds / .cci).</summary>
    Cci,
    /// <summary>CTR Importable Archive (.cia).</summary>
    Cia,
    /// <summary>Executable NCCH (.cxi / .app).</summary>
    Cxi,
    /// <summary>Data-only NCCH (.cfa).</summary>
    Cfa,
    /// <summary>Homebrew executable (.3dsx); nothing to decrypt or convert.</summary>
    ThreeDsx,
}

public static class CtrFile
{
    /// <summary>Recognized extensions, for file pickers and directory scans; the last four are Azahar's compressed (Z3DS) ones.</summary>
    public static readonly string[] Extensions = { ".3ds", ".cci", ".cia", ".cxi", ".cfa", ".app", ".3dsx", ".zcci", ".zcia", ".zcxi", ".z3dsx" };

    /// <summary>
    /// Detect the file type from its contents (extension is ignored). For a Z3DS file opened with
    /// <see cref="OpenRead"/> (or a <see cref="Z3dsReadStream"/>) this is the type of the file it holds.
    /// </summary>
    public static CtrFileType Detect(Stream s)
    {
        if (s.Length < 0x20) return CtrFileType.Unknown;
        int n = (int)Math.Min(0x200, s.Length);
        var head = VirtualStream.ReadBytesAt(s, 0, n);
        if (n >= 4 && head[0] == '3' && head[1] == 'D' && head[2] == 'S' && head[3] == 'X') return CtrFileType.ThreeDsx;
        if (n == 0x200 && NcsdHeader.IsNcsd(head)) return CtrFileType.Cci;
        if (n == 0x200 && NcchHeader.IsNcch(head))
            return (head[NcchHeader.FlagsOffset + 5] & 0x02) != 0 ? CtrFileType.Cxi : CtrFileType.Cfa;
        if (CiaFile.LooksLikeCia(head) && s.Length >= CiaFile.ArchiveHeaderSize) return CtrFileType.Cia;
        return CtrFileType.Unknown;
    }

    /// <summary>The type of the file at <paramref name="path"/>; for a .zcci/.zcia/.zcxi/.z3dsx, the type it holds.</summary>
    public static CtrFileType Detect(string path)
    {
        using var fs = OpenRead(path);
        return Detect(fs);
    }

    /// <summary>Whether the file is compressed with Azahar's Z3DS (.zcci, .zcia, .zcxi, .z3dsx).</summary>
    public static bool IsCompressed(string path) => Z3dsFile.IsZ3ds(path);

    /// <summary>
    /// Opens a 3DS file for reading. A Z3DS file comes back as the file it holds, decompressed as it's
    /// read, so every operation takes compressed and plain files alike.
    /// </summary>
    public static Stream OpenRead(string path)
    {
        var fs = OpenRaw(path);
        try
        {
            return Z3dsFile.IsZ3ds(fs) ? new Z3dsReadStream(fs) : fs;
        }
        catch
        {
            fs.Dispose();
            throw;
        }
    }

    internal static FileStream OpenRaw(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan);

    /// <summary>
    /// Region guessed from the last letter of the game code in a product code such as CTR-P-ABCE.
    /// DLC and update codes carry a suffix (CTR-M-ABCE-00); the game code is still the third part.
    /// </summary>
    public static string? RegionFromProductCode(string? productCode)
    {
        if (string.IsNullOrWhiteSpace(productCode)) return null;
        string[] parts = productCode.Trim().Split('-');
        string game = parts.Length >= 3 ? parts[2] : parts[^1];
        if (game.Length != 4) return null;
        return char.ToUpperInvariant(game[3]) switch
        {
            'A' => "World",
            'E' => "USA",
            'J' => "Japan",
            'P' or 'V' or 'X' or 'Y' or 'Z' => "Europe",
            'D' => "Germany",
            'F' => "France",
            'S' => "Spain",
            'I' => "Italy",
            'H' => "Netherlands",
            'U' => "Australia",
            'R' => "Russia",
            'K' => "Korea",
            'C' => "China",
            'W' => "Taiwan",
            _ => null,
        };
    }
}
