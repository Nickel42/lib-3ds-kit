using System.Buffers.Binary;
using System.Text;
using Lib3dsKit.IO;

namespace Lib3dsKit.Z3ds;

/// <summary>
/// The fixed 0x20-byte header at the start of a Z3DS file (Azahar's compressed .zcci/.zcia/.zcxi/.z3dsx).
/// All fields are little-endian.
/// </summary>
/// <param name="UnderlyingMagic">What the file holds once decompressed: "NCSD", "NCCH", "CIA" or "3DSX".</param>
/// <param name="Version">Format version; 1 is the only one defined.</param>
/// <param name="HeaderSize">Bytes before the metadata (0x20).</param>
/// <param name="MetadataSize">Bytes of metadata after the header, padded to 0x10.</param>
/// <param name="CompressedSize">Bytes of the seekable zstd stream after the metadata, its seek table included.</param>
/// <param name="UncompressedSize">Size of the file it holds.</param>
public sealed record Z3dsHeader(string UnderlyingMagic, byte Version, ushort HeaderSize, uint MetadataSize,
    ulong CompressedSize, ulong UncompressedSize)
{
    /// <summary>Where the zstd stream starts.</summary>
    public long DataOffset => HeaderSize + (long)MetadataSize;
}

/// <summary>
/// Azahar's Z3DS container: a 0x20-byte header, optional metadata (name → bytes), then the file
/// compressed in the zstd seekable format (independent frames plus a seek table), so any part of it
/// can be read without decompressing what comes before.
/// </summary>
public static class Z3dsFile
{
    public const int HeaderSize = 0x20;
    public const byte Version = 1;
    public const byte MetadataVersion = 1;

    /// <summary>Azahar's frame size for cartridge images, NCCHs and 3DSX: 256 KiB.</summary>
    public const int DefaultFrameSize = 256 * 1024;

    /// <summary>Azahar's frame size for CIAs: 32 MiB.</summary>
    public const int CiaFrameSize = 32 * 1024 * 1024;

    internal const uint SkippableSeekTableMagic = 0x184D2A5E;
    internal const uint SeekableMagic = 0x8F92EAB1;
    internal const int SeekTableFooterSize = 9;

    private static ReadOnlySpan<byte> Magic => "Z3DS"u8;

    /// <summary>Whether the stream starts with a Z3DS header this library can read.</summary>
    public static bool IsZ3ds(Stream s)
    {
        if (s.Length < HeaderSize) return false;
        Span<byte> head = stackalloc byte[9];
        VirtualStream.ReadExactlyAt(s, 0, head);
        return head[..4].SequenceEqual(Magic) && head[8] == Version;
    }

    public static bool IsZ3ds(string path)
    {
        using var fs = CtrFile.OpenRaw(path);
        return IsZ3ds(fs);
    }

    public static Z3dsHeader ReadHeader(Stream s)
    {
        if (s.Length < HeaderSize) throw new CtrFormatException("Too short for a Z3DS file.");
        var b = VirtualStream.ReadBytesAt(s, 0, HeaderSize);
        if (!b.AsSpan(0, 4).SequenceEqual(Magic)) throw new CtrFormatException("Not a Z3DS file.");
        if (b[8] != Version) throw new CtrFormatException($"Z3DS version {b[8]} is not supported (only {Version}).");
        var header = new Z3dsHeader(
            Encoding.ASCII.GetString(b, 4, 4).TrimEnd('\0'),
            b[8],
            BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(0x0A)),
            BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(0x0C)),
            BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(0x10)),
            BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(0x18)));
        if (header.HeaderSize < HeaderSize || header.DataOffset > s.Length)
            throw new CtrFormatException("Z3DS header sizes point past the end of the file.");
        return header;
    }

    /// <summary>The metadata items (Azahar writes "compressor", "date", "maxframesize", and for games "titleinfo"/"smdh").</summary>
    public static IReadOnlyDictionary<string, byte[]> ReadMetadata(Stream s)
    {
        var header = ReadHeader(s);
        return header.MetadataSize == 0
            ? new Dictionary<string, byte[]>()
            : ParseMetadata(VirtualStream.ReadBytesAt(s, header.HeaderSize, (int)header.MetadataSize));
    }

    /// <summary>The extension Azahar gives a compressed file of this type (".zcci", ".zcia", ".zcxi", ".z3dsx").</summary>
    public static string CompressedExtension(CtrFileType type) => type switch
    {
        CtrFileType.Cci => ".zcci",
        CtrFileType.Cia => ".zcia",
        CtrFileType.Cxi or CtrFileType.Cfa => ".zcxi",
        CtrFileType.ThreeDsx => ".z3dsx",
        _ => throw new CtrFormatException($"{type} files can't be compressed."),
    };

    /// <summary>The extension of the plain file a Z3DS file holds (".cci", ".cia", ".cxi", ".3dsx").</summary>
    public static string PlainExtension(CtrFileType type) => type switch
    {
        CtrFileType.Cci => ".cci",
        CtrFileType.Cia => ".cia",
        CtrFileType.Cxi or CtrFileType.Cfa => ".cxi",
        CtrFileType.ThreeDsx => ".3dsx",
        _ => throw new CtrFormatException($"{type} has no plain extension."),
    };

    /// <summary>The magic Azahar records for each type: NCSD for cartridge images, NCCH for CXI/CFA, CIA, 3DSX.</summary>
    internal static byte[] UnderlyingMagicOf(CtrFileType type) => type switch
    {
        CtrFileType.Cci => "NCSD"u8.ToArray(),
        CtrFileType.Cxi or CtrFileType.Cfa => "NCCH"u8.ToArray(),
        CtrFileType.Cia => [(byte)'C', (byte)'I', (byte)'A', 0],
        CtrFileType.ThreeDsx => "3DSX"u8.ToArray(),
        _ => throw new CtrFormatException($"{type} files can't be compressed."),
    };

    /// <summary>The frame size Azahar uses for this type.</summary>
    public static int FrameSizeFor(CtrFileType type) => type == CtrFileType.Cia ? CiaFrameSize : DefaultFrameSize;

    internal static byte[] BuildHeader(ReadOnlySpan<byte> underlyingMagic, uint metadataSize, ulong compressedSize, ulong uncompressedSize)
    {
        var b = new byte[HeaderSize];
        Magic.CopyTo(b);
        underlyingMagic.CopyTo(b.AsSpan(4, 4));
        b[8] = Version;
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(0x0A), HeaderSize);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(0x0C), metadataSize);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(0x10), compressedSize);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(0x18), uncompressedSize);
        return b;
    }

    /// <summary>
    /// Metadata block: a version byte, then items of (type u8, name length u8, data length u16, name, data),
    /// ended by an all-zero item and padded with zeros to 0x10. Type 1 is binary; other types are skipped.
    /// </summary>
    internal static byte[] BuildMetadata(IEnumerable<KeyValuePair<string, byte[]>> items)
    {
        var list = items.ToList();
        if (list.Count == 0) return [];
        using var ms = new MemoryStream();
        ms.WriteByte(MetadataVersion);
        Span<byte> len = stackalloc byte[2];
        foreach (var (name, data) in list)
        {
            var n = Encoding.UTF8.GetBytes(name);
            int nameLen = Math.Min(n.Length, 0xFF), dataLen = Math.Min(data.Length, 0xFFFF);
            ms.WriteByte(1);
            ms.WriteByte((byte)nameLen);
            BinaryPrimitives.WriteUInt16LittleEndian(len, (ushort)dataLen);
            ms.Write(len);
            ms.Write(n, 0, nameLen);
            ms.Write(data, 0, dataLen);
        }
        ms.Write(new byte[4]); // the end item
        while (ms.Length % 0x10 != 0) ms.WriteByte(0);
        return ms.ToArray();
    }

    internal static Dictionary<string, byte[]> ParseMetadata(byte[] b)
    {
        var items = new Dictionary<string, byte[]>();
        if (b.Length == 0 || b[0] != MetadataVersion) return items;
        int p = 1;
        while (p + 4 <= b.Length)
        {
            byte type = b[p], nameLen = b[p + 1];
            int dataLen = BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(p + 2));
            p += 4;
            if (type == 0) break;
            if (p + nameLen + dataLen > b.Length) break;
            if (type == 1) items[Encoding.UTF8.GetString(b, p, nameLen)] = b.AsSpan(p + nameLen, dataLen).ToArray();
            p += nameLen + dataLen;
        }
        return items;
    }
}

/// <summary>One frame of a seekable zstd stream: where it is and how big it is either side of compression.</summary>
internal readonly record struct SeekFrame(long CompressedOffset, int CompressedSize, long DecompressedOffset, int DecompressedSize);

/// <summary>The zstd seekable format's seek table: a skippable frame at the end of the stream listing every frame.</summary>
internal static class SeekTable
{
    /// <summary>Reads the seek table of the zstd stream at [<paramref name="start"/>, <paramref name="start"/> + <paramref name="length"/>).</summary>
    public static List<SeekFrame> Read(Stream s, long start, long length)
    {
        if (length < Z3dsFile.SeekTableFooterSize + 8) throw new CtrFormatException("Z3DS data is too short for a seek table.");
        var footer = VirtualStream.ReadBytesAt(s, start + length - Z3dsFile.SeekTableFooterSize, Z3dsFile.SeekTableFooterSize);
        if (BinaryPrimitives.ReadUInt32LittleEndian(footer.AsSpan(5)) != Z3dsFile.SeekableMagic)
            throw new CtrFormatException("Z3DS data has no zstd seek table.");
        uint frames = BinaryPrimitives.ReadUInt32LittleEndian(footer);
        byte descriptor = footer[4];
        if ((descriptor & 0x7C) != 0) throw new CtrFormatException("Z3DS seek table uses reserved bits.");
        int entrySize = (descriptor & 0x80) != 0 ? 12 : 8;
        long tableSize = (long)frames * entrySize;
        long frameStart = start + length - Z3dsFile.SeekTableFooterSize - tableSize - 8;
        if (frameStart < start || tableSize > int.MaxValue) throw new CtrFormatException("Z3DS seek table is larger than its data.");
        var head = VirtualStream.ReadBytesAt(s, frameStart, 8);
        if (BinaryPrimitives.ReadUInt32LittleEndian(head) != Z3dsFile.SkippableSeekTableMagic
            || BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(4)) != tableSize + Z3dsFile.SeekTableFooterSize)
            throw new CtrFormatException("Z3DS seek table frame is damaged.");
        var table = VirtualStream.ReadBytesAt(s, frameStart + 8, (int)tableSize);
        var list = new List<SeekFrame>((int)frames);
        long c = start, d = 0;
        for (int i = 0; i < frames; i++)
        {
            var e = table.AsSpan(i * entrySize);
            int cs = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(e));
            int ds = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(e[4..]));
            list.Add(new SeekFrame(c, cs, d, ds));
            c += cs;
            d += ds;
        }
        if (c != frameStart) throw new CtrFormatException("Z3DS seek table doesn't add up to its data.");
        return list;
    }

    /// <summary>The seek table frame for these frames, without checksums (as Azahar writes it).</summary>
    public static byte[] Build(IReadOnlyList<(int Compressed, int Decompressed)> frames)
    {
        int tableSize = frames.Count * 8;
        var b = new byte[8 + tableSize + Z3dsFile.SeekTableFooterSize];
        BinaryPrimitives.WriteUInt32LittleEndian(b, Z3dsFile.SkippableSeekTableMagic);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4), (uint)(tableSize + Z3dsFile.SeekTableFooterSize));
        for (int i = 0; i < frames.Count; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8 + i * 8), (uint)frames[i].Compressed);
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(12 + i * 8), (uint)frames[i].Decompressed);
        }
        var footer = b.AsSpan(8 + tableSize);
        BinaryPrimitives.WriteUInt32LittleEndian(footer, (uint)frames.Count);
        footer[4] = 0; // no checksums
        BinaryPrimitives.WriteUInt32LittleEndian(footer[5..], Z3dsFile.SeekableMagic);
        return b;
    }
}
