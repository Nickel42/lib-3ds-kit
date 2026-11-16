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

    [Theory]
    [InlineData(0L)]
    [InlineData(5L)]
    [InlineData(0x1234567L)]
    public void AesCtr_LongRangeSplitAcrossCores_MatchesSmallPieces(long offset)
    {
        var key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");
        var counter = new UInt128(0x0123456789abcdef, 0xffffffffffffff00); // carries out of the low half
        var data = new byte[3 * Crypto.AesCtrCipher.ParallelThreshold + 37];
        new Random(5).NextBytes(data);
        var whole = (byte[])data.Clone();
        var pieces = (byte[])data.Clone();
        using var c = new Crypto.AesCtrCipher(key);
        c.Transform(counter, offset, whole);
        for (int p = 0; p < pieces.Length; p += 4093)
            c.Transform(counter, offset + p, pieces.AsSpan(p, Math.Min(4093, pieces.Length - p)));
        Assert.True(whole.AsSpan().SequenceEqual(pieces));
        c.Transform(counter, offset, whole);
        Assert.True(whole.AsSpan().SequenceEqual(data)); // CTR undoes itself
    }

    [Fact]
    public void AesCbcStream_InPlaceAndBufferedReads_MatchOneShotDecryption()
    {
        var key = Convert.FromHexString("00112233445566778899aabbccddeeff");
        var iv = Convert.FromHexString("0f0e0d0c0b0a09080706050403020100");
        var plain = new byte[300_000 * 16];
        new Random(3).NextBytes(plain);
        var cipher = Crypto.AesUtil.CbcEncrypt(key, iv, plain);
        using var cbc = new Crypto.AesCbcDecryptStream(new MemoryStream(cipher), key, iv);

        // Aligned reads straight through (in place, IV carried over), unaligned ones, and jumps.
        var back = new byte[plain.Length];
        var rng = new Random(4);
        for (int p = 0; p < back.Length;)
        {
            int n = Math.Min(back.Length - p, rng.Next(2) == 0 ? 16 * rng.Next(1, 20_000) : rng.Next(1, 100_000));
            cbc.Position = p;
            cbc.ReadExactly(back, p, n);
            p += n;
        }
        Assert.True(plain.AsSpan().SequenceEqual(back));
        for (int i = 0; i < 100; i++)
        {
            int p = rng.Next(plain.Length), n = Math.Min(plain.Length - p, rng.Next(1, 50_000));
            if (rng.Next(2) == 0) { p &= ~15; n = Math.Max(16, n & ~15); n = Math.Min(n, plain.Length - p); }
            var buf = new byte[n];
            cbc.Position = p;
            cbc.ReadExactly(buf);
            Assert.True(plain.AsSpan(p, n).SequenceEqual(buf), $"bytes differ at {p}+{n}");
        }
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
