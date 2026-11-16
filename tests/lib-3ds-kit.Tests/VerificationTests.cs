using Lib3dsKit.Hashing;
using Lib3dsKit.Keys;
using Lib3dsKit.Ncch;
using Lib3dsKit.Verification;
using Xunit;

namespace Lib3dsKit.Tests;

public class VerificationTests
{
    [Fact]
    public void Inspect_Cci_ReadsMetadata()
    {
        var info = CtrInspector.Inspect(Fixtures.File("game_a.3ds"), Fixtures.Keys());
        Assert.Equal(CtrFileType.Cci, info.Type);
        Assert.Equal(Fixtures.Fact("game_a_title_id"), info.TitleIdHex);
        Assert.Equal(Fixtures.Fact("game_a_product"), info.ProductCode);
        Assert.Equal("USA", info.Region);
        Assert.Equal(Fixtures.Fact("game_a_title"), info.Titles?.ShortTitle);
        Assert.Equal(Fixtures.Fact("game_a_publisher"), info.Titles?.Publisher);
        Assert.Equal(long.Parse(Fixtures.Fact("game_a_media_size")), info.MediaSize);
        Assert.Equal(long.Parse(Fixtures.Fact("game_a_used_size")), info.UsedSize);
        Assert.True(info.IsTrimmed);
        Assert.True(info.Encrypted);
        Assert.Equal(0x80000UL, info.SaveDataSize);
        Assert.Equal(2, info.Ncchs.Count);
        Assert.All(info.Ncchs, n => Assert.True(n.CanDecrypt));
        Assert.Equal("7.x (0x25)", info.Ncchs[0].Crypto);
    }

    [Fact]
    public void Inspect_WithoutKeys_ReportsMissingKey()
    {
        var info = CtrInspector.Inspect(Fixtures.File("game_a.3ds"));
        Assert.Null(info.Titles);
        Assert.Equal("CTR-P-ATGE", info.ProductCode); // header is plaintext
        Assert.All(info.Ncchs, n => Assert.False(n.CanDecrypt));
        Assert.Equal("slot0x2CKeyX", info.Ncchs[0].MissingKey);
    }

    [Fact]
    public void Inspect_Cia_ReadsMetadata()
    {
        var info = CtrInspector.Inspect(Fixtures.File("game_b.cia"), Fixtures.Keys());
        Assert.Equal(CtrFileType.Cia, info.Type);
        Assert.Equal(Fixtures.Fact("game_b_title_id"), info.TitleIdHex);
        Assert.Equal(Fixtures.Fact("game_b_product"), info.ProductCode);
        Assert.Equal("Japan", info.Region);
        Assert.Equal("Seed Game", info.Titles?.ShortTitle);
        Assert.Contains("seed", info.Ncchs[0].Crypto);
    }

    [Fact]
    public void Inspect_Cia_WithoutKeys_FallsBackToMetaIcon()
    {
        var info = CtrInspector.Inspect(Fixtures.File("game_b.cia"));
        Assert.Equal("Seed Game", info.Titles?.ShortTitle);
    }

    [Fact]
    public async Task Verify_TrimmedEncryptedCci_IsIntact()
    {
        var r = await new CtrVerifier(Fixtures.Keys()).VerifyAsync(Fixtures.File("game_a.3ds"));
        Assert.Equal(CtrVerdict.Intact, r.Verdict);
        Assert.Equal(Fixtures.Sha256OfFile(Fixtures.File("game_a.3ds")), r.Hashes.Sha256);
        Assert.NotEmpty(r.Checks);
        Assert.All(r.Checks, c => Assert.Equal(CheckStatus.Pass, c.Status));
    }

    [Fact]
    public async Task Verify_DecryptedCci_IsIntact()
    {
        var r = await new CtrVerifier(Fixtures.Keys()).VerifyAsync(Fixtures.File("expected/game_a.decrypted.3ds"));
        Assert.Equal(CtrVerdict.Intact, r.Verdict);
        Assert.Equal(Fixtures.ExpectedSha256("game_a.decrypted.3ds"), r.Hashes.Sha256);
    }

    [Fact]
    public async Task Verify_WithoutHashes_SkipsTheWholeFilePass_ButNotTheChecks()
    {
        var r = await new CtrVerifier(Fixtures.Keys()).VerifyAsync(Fixtures.File("game_a.3ds"),
            new CtrVerifyOptions { HashKinds = HashKinds.None });
        Assert.Equal(CtrVerdict.Intact, r.Verdict);
        Assert.Equal(new FileInfo(Fixtures.File("game_a.3ds")).Length, r.Hashes.Size);
        Assert.Null(r.Hashes.Crc32);
        Assert.Null(r.Hashes.Sha256);
        Assert.NotEmpty(r.Checks);
    }

    [Fact]
    public async Task Verify_WithoutHashes_StillReadsEveryFrameOfACompressedFile()
    {
        using var tmp = new TempDir();
        string z = tmp.File("a.zcci");
        await new Operations.CtrConverter(Fixtures.Keys()).CompressAsync(Fixtures.File("expected/game_a.decrypted.3ds"), z,
            new Operations.CtrConvertOptions { CompressionFrameSize = 4096 });
        var none = new CtrVerifyOptions { HashKinds = HashKinds.None };
        Assert.Equal(CtrVerdict.Intact, (await new CtrVerifier(Fixtures.Keys()).VerifyAsync(z, none)).Verdict);

        // Damage the last frame, which no header check reads.
        var file = File.ReadAllBytes(z);
        using (var rs = new Z3ds.Z3dsReadStream(new MemoryStream(file)))
        {
            long end = rs.Header.DataOffset + (long)rs.Header.CompressedSize;
            int frames = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan((int)end - 9));
            int tableStart = (int)end - 9 - frames * 8 - 8;
            int lastSize = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(tableStart + 8 + (frames - 1) * 8));
            file[tableStart - lastSize + 6] ^= 0xFF;
        }
        File.WriteAllBytes(z, file);
        await Assert.ThrowsAsync<CtrFormatException>(() => new CtrVerifier(Fixtures.Keys()).VerifyAsync(z, none));
    }

    [Fact]
    public async Task Verify_Cia_PassesTmdChecks()
    {
        var r = await new CtrVerifier(Fixtures.Keys()).VerifyAsync(Fixtures.File("game_b.cia"));
        Assert.Equal(CtrVerdict.Intact, r.Verdict);
        Assert.Contains(r.Checks, c => c.Name.Contains("TMD SHA-256") && c.Status == CheckStatus.Pass);
        Assert.All(r.Checks, c => Assert.Equal(CheckStatus.Pass, c.Status));
    }

    [Fact]
    public async Task Verify_ConvertedCia_IsIntact()
    {
        var r = await new CtrVerifier(Fixtures.Keys()).VerifyAsync(Fixtures.File("expected/game_a.cia"));
        Assert.Equal(CtrVerdict.Intact, r.Verdict);
    }

    [Fact]
    public async Task Verify_CorruptedFile_IsBad()
    {
        using var tmp = new TempDir();
        string bad = tmp.File("bad.3ds");
        byte[] data = File.ReadAllBytes(Fixtures.File("expected/game_a.decrypted.3ds"));
        // flip one bit inside the manual's RomFS superblock (covered by the header hash)
        var info = CtrInspector.Inspect(Fixtures.File("expected/game_a.decrypted.3ds"));
        long p1 = info.Ncchs[1].Offset;
        var hdr = new NcchHeader(data.AsSpan((int)p1, 0x200));
        data[p1 + hdr.RomFs.Offset + 5] ^= 0x01;
        File.WriteAllBytes(bad, data);
        var r = await new CtrVerifier(new CtrKeyStore()).VerifyAsync(bad);
        Assert.Equal(CtrVerdict.Bad, r.Verdict);
        Assert.Contains(r.Checks, c => c.Status == CheckStatus.Fail && c.Name.Contains("RomFS"));
    }

    [Fact]
    public async Task Verify_WithoutKeys_SkipsEncryptedChecks()
    {
        var r = await new CtrVerifier(new CtrKeyStore()).VerifyAsync(Fixtures.File("game_a.3ds"));
        Assert.Equal(CtrVerdict.Unknown, r.Verdict);
        Assert.All(r.Checks, c => Assert.Equal(CheckStatus.Skipped, c.Status));
    }

    [Fact]
    public void KeyScrambler_MatchesReferenceVector()
    {
        var n = KeyScrambler.Generate(Convert.FromHexString(Fixtures.Fact("scrambler_x")),
            Convert.FromHexString(Fixtures.Fact("scrambler_y")));
        Assert.Equal(Fixtures.Fact("scrambler_normal"), Convert.ToHexString(n).ToLowerInvariant());
    }

    [Fact]
    public void Boot9_UnknownHash_RejectedByDefault()
    {
        var ks = new CtrKeyStore();
        Assert.Throws<CtrFormatException>(() => ks.LoadBoot9(File.ReadAllBytes(Fixtures.File("keys/boot9_fake.bin"))));
    }

    [Fact]
    public void KeyStatus_ReflectsLoadedKeys()
    {
        var s = Fixtures.Keys().GetStatus();
        Assert.True(s.IsRetailReady);
        Assert.Equal(6, s.CommonKeyYCount);
        Assert.Equal(1, s.SeedCount);
        Assert.False(new CtrKeyStore().GetStatus().IsRetailReady);
    }

    [Fact]
    public void Crc32_KnownVector()
    {
        Assert.Equal(0xCBF43926u, Crc32.Compute("123456789"u8));
        Assert.Equal(0u, Crc32.Compute(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void Detect_RecognizesAllFixtureTypes()
    {
        Assert.Equal(CtrFileType.Cci, CtrFile.Detect(Fixtures.File("game_a.3ds")));
        Assert.Equal(CtrFileType.Cia, CtrFile.Detect(Fixtures.File("game_b.cia")));
        Assert.Equal(CtrFileType.Cxi, CtrFile.Detect(Fixtures.File("system_fixed.cxi")));
        Assert.Equal(CtrFileType.Unknown, CtrFile.Detect(Fixtures.File("keys/aes_keys_fake.txt")));
    }
}
