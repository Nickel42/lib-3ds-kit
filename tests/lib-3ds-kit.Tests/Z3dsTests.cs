using System.Buffers.Binary;
using Lib3dsKit.Operations;
using Lib3dsKit.Verification;
using Lib3dsKit.Z3ds;
using Xunit;

namespace Lib3dsKit.Tests;

/// <summary>Azahar's Z3DS format (.zcci, .zcia, .zcxi, .z3dsx): writing, reading, and every operation taking it as input.</summary>
public class Z3dsTests
{
    private static CtrConverter Converter() => new(Fixtures.Keys());

    [Theory]
    [InlineData("game_a.3ds", "NCSD", ".zcci", CtrFileType.Cci)]
    [InlineData("game_b.cia", "CIA", ".zcia", CtrFileType.Cia)]
    [InlineData("system_fixed.cxi", "NCCH", ".zcxi", CtrFileType.Cxi)]
    public async Task Compress_ThenDecompress_GivesTheSameBytes(string input, string magic, string ext, CtrFileType type)
    {
        using var tmp = new TempDir();
        string z = tmp.File("out" + ext), plain = tmp.File("back.bin");
        var c = await Converter().CompressAsync(Fixtures.File(input), z);
        Assert.True(c.Compressed);
        Assert.Equal(type, c.OutputType);
        Assert.Equal(Fixtures.Sha256OfFile(Fixtures.File(input)), c.OutputHashes!.Sha256); // hashes of the plain file

        using (var fs = File.OpenRead(z))
        {
            var h = Z3dsFile.ReadHeader(fs);
            Assert.Equal(magic, h.UnderlyingMagic);
            Assert.Equal(1, h.Version);
            Assert.Equal(0x20, h.HeaderSize);
            Assert.Equal(0u, h.MetadataSize % 0x10);
            Assert.Equal((ulong)new FileInfo(Fixtures.File(input)).Length, h.UncompressedSize);
            Assert.Equal((ulong)(fs.Length - h.DataOffset), h.CompressedSize);
            var meta = Z3dsFile.ReadMetadata(fs);
            Assert.Equal("lib-3ds-kit"u8.ToArray(), meta["compressor"]);
            Assert.Equal(Z3dsFile.FrameSizeFor(type).ToString(), System.Text.Encoding.ASCII.GetString(meta["maxframesize"]));
        }
        Assert.True(CtrFile.IsCompressed(z));
        Assert.Equal(type, CtrFile.Detect(z));

        var d = await Converter().DecompressAsync(z, plain);
        Assert.False(d.Compressed);
        Assert.Equal(Fixtures.Sha256OfFile(Fixtures.File(input)), Fixtures.Sha256OfFile(plain));
    }

    [Fact]
    public void ReadStream_ReadsAnyRangeAcrossManySmallFrames()
    {
        using var tmp = new TempDir();
        string input = Fixtures.File("game_a.3ds"), z = tmp.File("small.zcci");
        Converter().Compress(input, z, new CtrConvertOptions { CompressionFrameSize = 4096 });
        var plain = File.ReadAllBytes(input);
        using var rs = new Z3dsReadStream(File.OpenRead(z));
        Assert.Equal(plain.Length, rs.Length);
        Assert.True(rs.FrameCount > 4, $"only {rs.FrameCount} frames");
        var rng = new Random(1234);
        for (int i = 0; i < 200; i++)
        {
            int start = rng.Next(plain.Length), len = Math.Min(plain.Length - start, rng.Next(1, 20000));
            var buf = new byte[len];
            rs.Position = start;
            rs.ReadExactly(buf);
            Assert.True(plain.AsSpan(start, len).SequenceEqual(buf), $"bytes differ at {start}+{len}");
        }
    }

    [Fact]
    public void EveryFrameIsAStandaloneZstdFrameListedInTheSeekTable()
    {
        using var tmp = new TempDir();
        string input = Fixtures.File("game_a.3ds"), z = tmp.File("frames.zcci");
        Converter().Compress(input, z, new CtrConvertOptions { CompressionFrameSize = 8192 });
        var plain = File.ReadAllBytes(input);
        var file = File.ReadAllBytes(z);
        using var fs = new MemoryStream(file);
        var h = Z3dsFile.ReadHeader(fs);
        var end = (int)(h.DataOffset + (long)h.CompressedSize);

        // The footer and the skippable frame that holds the seek table, as the zstd seekable format defines them.
        Assert.Equal(0x8F92EAB1u, BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(end - 4)));
        Assert.Equal(0, file[end - 5]); // no checksums, like Azahar
        int frames = (int)BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(end - 9));
        int tableStart = end - 9 - frames * 8 - 8;
        Assert.Equal(0x184D2A5Eu, BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(tableStart)));
        Assert.Equal((uint)(frames * 8 + 9), BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(tableStart + 4)));
        Assert.Equal((plain.Length + 8191) / 8192, frames);

        using var zstd = new ZstdSharp.Decompressor();
        int c = (int)h.DataOffset, d = 0;
        for (int i = 0; i < frames; i++)
        {
            int cs = (int)BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(tableStart + 8 + i * 8));
            int ds = (int)BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(tableStart + 12 + i * 8));
            Assert.Equal(0xFD2FB528u, BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(c))); // a zstd frame
            var outBuf = new byte[ds];
            Assert.Equal(ds, zstd.Unwrap(file.AsSpan(c, cs), outBuf));
            Assert.True(plain.AsSpan(d, ds).SequenceEqual(outBuf), $"frame {i}");
            c += cs;
            d += ds;
        }
        Assert.Equal(tableStart, c);
        Assert.Equal(plain.Length, d);
    }

    [Fact]
    public async Task Decrypt_ReadsACompressedCci()
    {
        using var tmp = new TempDir();
        string z = tmp.File("a.zcci"), output = tmp.File("a.3ds");
        await Converter().CompressAsync(Fixtures.File("game_a.3ds"), z);
        var r = await Converter().DecryptAsync(z, output);
        Assert.Equal(Fixtures.ExpectedSha256("game_a.decrypted.3ds"), Fixtures.Sha256OfFile(output));
        Assert.False(r.Compressed);
    }

    [Fact]
    public async Task CiaToCci_Compressed_HoldsTheReferenceCci()
    {
        using var tmp = new TempDir();
        string z = tmp.File("b.zcci"), back = tmp.File("b.3ds");
        var r = await Converter().ConvertAsync(Fixtures.File("game_b.cia"), z, CtrOutputFormat.Cci, new CtrConvertOptions { Compress = true });
        Assert.True(r.Compressed);
        Assert.True(CtrFile.IsCompressed(z));
        Assert.Equal(Fixtures.ExpectedSha256("game_b.3ds"), r.OutputHashes!.Sha256);
        await Converter().DecompressAsync(z, back);
        Assert.Equal(Fixtures.ExpectedSha256("game_b.3ds"), Fixtures.Sha256OfFile(back));
    }

    [Fact]
    public async Task CciToCia_Compressed_HoldsTheReferenceCia_AndLeavesNoPlainFile()
    {
        using var tmp = new TempDir();
        string z = tmp.File("a.zcia"), back = tmp.File("a.cia");
        var r = await Converter().ConvertAsync(Fixtures.File("game_a.3ds"), z, CtrOutputFormat.Cia, new CtrConvertOptions { Compress = true });
        Assert.True(r.Compressed);
        Assert.Equal(Fixtures.ExpectedSha256("game_a.cia"), r.OutputHashes!.Sha256);
        using (var fs = File.OpenRead(z)) Assert.Equal("CIA", Z3dsFile.ReadHeader(fs).UnderlyingMagic);
        await Converter().DecompressAsync(z, back);
        Assert.Equal(Fixtures.ExpectedSha256("game_a.cia"), Fixtures.Sha256OfFile(back));
        Assert.Equal(new[] { "a.cia", "a.zcia" }, Directory.GetFiles(tmp.Path).Select(Path.GetFileName).Order().ToArray());
    }

    [Fact]
    public async Task InspectAndVerify_SeeTheFileACompressedOneHolds()
    {
        using var tmp = new TempDir();
        string z = tmp.File("a.zcci");
        await Converter().CompressAsync(Fixtures.File("game_a.3ds"), z);
        var plainInfo = CtrInspector.Inspect(Fixtures.File("game_a.3ds"), Fixtures.Keys());
        var info = CtrInspector.Inspect(z, Fixtures.Keys());
        Assert.True(info.Compressed);
        Assert.False(plainInfo.Compressed);
        Assert.Equal(CtrFileType.Cci, info.Type);
        Assert.Equal(plainInfo.TitleId, info.TitleId);
        Assert.Equal(plainInfo.FileSize, info.FileSize);

        var report = await new CtrVerifier(Fixtures.Keys()).VerifyAsync(z);
        var plainReport = await new CtrVerifier(Fixtures.Keys()).VerifyAsync(Fixtures.File("game_a.3ds"));
        Assert.Equal(plainReport.Hashes.Sha1, report.Hashes.Sha1);
        Assert.Equal(plainReport.Verdict, report.Verdict);
    }

    [Fact]
    public async Task Compress_RefusesACompressedFileAndAnExistingOutput()
    {
        using var tmp = new TempDir();
        string z = tmp.File("a.zcci");
        await Converter().CompressAsync(Fixtures.File("game_a.3ds"), z);
        await Assert.ThrowsAsync<CtrFormatException>(() => Converter().CompressAsync(z, tmp.File("again.zcci")));
        await Assert.ThrowsAsync<IOException>(() => Converter().CompressAsync(Fixtures.File("game_a.3ds"), z));
        await Assert.ThrowsAsync<CtrFormatException>(() => Converter().DecompressAsync(Fixtures.File("game_a.3ds"), tmp.File("x.3ds")));
        Assert.Single(Directory.GetFiles(tmp.Path)); // nothing half-written left behind
    }

    [Fact]
    public async Task DamagedFiles_AreReportedNotMisread()
    {
        using var tmp = new TempDir();
        string z = tmp.File("a.zcci");
        await Converter().CompressAsync(Fixtures.File("game_a.3ds"), z, new CtrConvertOptions { CompressionFrameSize = 4096 });
        var good = File.ReadAllBytes(z);

        var noTable = (byte[])good.Clone();
        noTable[^1] ^= 0xFF; // the seekable magic
        File.WriteAllBytes(z, noTable);
        Assert.Throws<CtrFormatException>(() => CtrFile.Detect(z));

        var badFrame = (byte[])good.Clone();
        using (var ms = new MemoryStream(good)) badFrame[(int)Z3dsFile.ReadHeader(ms).DataOffset + 8] ^= 0xFF;
        File.WriteAllBytes(z, badFrame);
        await Assert.ThrowsAsync<CtrFormatException>(() => Converter().DecompressAsync(z, tmp.File("x.3ds")));

        File.WriteAllBytes(z, good[..(good.Length - 100)]);
        Assert.Throws<CtrFormatException>(() => CtrFile.Detect(z));
    }

    /// <summary>
    /// Files Azahar itself made (2123, <c>azahar -c</c>) from the decrypted reference fixtures: this library reads them
    /// back byte for byte. The other direction (<c>azahar -x</c> on this library's files) was checked by hand.
    /// </summary>
    [Theory]
    [InlineData("azahar/game_a.decrypted.zcci", "game_a.decrypted.3ds", "NCSD", CtrFileType.Cci)]
    [InlineData("azahar/game_b.decrypted.zcia", "game_b.decrypted.cia", "CIA", CtrFileType.Cia)]
    public async Task ReadsFilesAzaharMade(string fixture, string expected, string magic, CtrFileType type)
    {
        using var tmp = new TempDir();
        string input = Fixtures.File(fixture), back = tmp.File("back.bin");
        using (var fs = File.OpenRead(input))
        {
            Assert.Equal(magic, Z3dsFile.ReadHeader(fs).UnderlyingMagic);
            Assert.StartsWith("Azahar", System.Text.Encoding.ASCII.GetString(Z3dsFile.ReadMetadata(fs)["compressor"]));
        }
        Assert.Equal(type, CtrFile.Detect(input));
        await Converter().DecompressAsync(input, back);
        Assert.Equal(Fixtures.ExpectedSha256(expected), Fixtures.Sha256OfFile(back));
    }

    [Fact]
    public void Metadata_RoundTripsAndSkipsUnknownItems()
    {
        var bytes = Z3dsFile.BuildMetadata(new Dictionary<string, byte[]> { ["a"] = [1, 2, 3], ["name"] = "value"u8.ToArray() });
        Assert.Equal(0, bytes.Length % 0x10);
        var back = Z3dsFile.ParseMetadata(bytes);
        Assert.Equal([1, 2, 3], back["a"]);
        Assert.Equal("value"u8.ToArray(), back["name"]);

        // An item of a type it doesn't know (2) is skipped, not misread.
        byte[] odd = [1, 2, 1, 1, 0, (byte)'x', 9, 1, 1, 1, 0, (byte)'y', 7, 0, 0, 0, 0];
        var parsed = Z3dsFile.ParseMetadata(odd);
        Assert.False(parsed.ContainsKey("x"));
        Assert.Equal([7], parsed["y"]);
    }
}
