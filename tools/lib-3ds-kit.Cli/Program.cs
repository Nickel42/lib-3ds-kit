using Lib3dsKit.IO;
using Lib3dsKit;
using Lib3dsKit.Keys;
using Lib3dsKit.Ncch;
using Lib3dsKit.Operations;
using Lib3dsKit.Verification;
using Lib3dsKit.Z3ds;

namespace Lib3dsKit.Cli;

internal static class Program
{
    private const string Usage = """
        3ds-kit - convert and decrypt Nintendo 3DS files (lib-3ds-kit)

        Usage: 3ds-kit [options] <command> [arguments]

        Commands:
          keys                          Show which keys/seeds were found and loaded
          info <file>                   Show metadata (title, IDs, encryption, partitions)
          decrypt <in> [out]            Decrypt a .3ds/.cci, .cia, .cxi or .cfa (format kept)
          convert <in> --to cci|cia [out]
                                        Convert between CCI and CIA (decrypted by default)
                                        <in> may also be a CDN folder (tmd, cetk and content
                                        files) for --to cia, or for decrypt
          trim <in> [out]               Trim a CCI to the end of its last partition
          untrim <in> [out]             Pad a trimmed CCI back to its card size
          verify <file|dir>...          Hash files and check the hashes stored inside them
          compress <in> [out]           Compress as Azahar's Z3DS (.zcci/.zcia/.zcxi/.z3dsx), as is
          decompress <in> [out]         Decompress a Z3DS file back to the file it holds

        Every command reads Z3DS files (.zcci, .zcia, .zcxi, .z3dsx) as well as plain ones.

        Key options (keys are never bundled; point at your own dumps):
          --keys-dir <dir>              Extra folder to search for boot9.bin/aes_keys.txt/seeddb.bin
          --boot9 <file>  --aes-keys <file>  --seeddb <file>
          --certs-from <cia>            Take the CIA certificate chain from a CIA you own
          --allow-unknown-boot9         Accept a boot9 whose hash is not a retail dump (testing)

        Other options:
          --keep-encryption             convert: keep NCCH encryption
          --compress                    decrypt/convert: write the result as Z3DS (.zcci, .zcia…)
          --level <n>                   zstd level for Z3DS output (default 3, as Azahar)
          --no-trim                     convert to CCI: pad to full card size
          --match-ticket-version        CDN: write the TMD's title version into the ticket
          --no-verify-contents          CDN: skip checking contents against the TMD
          --overwrite                   Replace existing output files
          --no-integrity                verify: skip internal hash checks
          --recursive                   verify: include subfolders
        """;

    private static async Task<int> Main(string[] argv)
    {
        Args args;
        try { args = new Args(argv); }
        catch (UsageException ex)
        {
            Console.Error.WriteLine("error: " + ex.Message);
            return 1;
        }
        if (args.Positionals.Count == 0 || args.Has("--help") || args.Has("-h"))
        {
            Console.WriteLine(Usage);
            return args.Positionals.Count == 0 && !args.Has("--help") && !args.Has("-h") ? 1 : 0;
        }
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
        try
        {
            var keys = LoadKeys(args);
            string cmd = args.Positionals[0].ToLowerInvariant();
            var rest = args.Positionals.Skip(1).ToList();
            return cmd switch
            {
                "keys" => ShowKeys(keys),
                "info" => Info(keys, Require(rest, 1, "info <file>")[0]),
                "decrypt" => await Decrypt(keys, args, rest, cts.Token),
                "convert" => await Convert(keys, args, rest, cts.Token),
                "trim" => await TrimOrUntrim(keys, args, rest, trim: true, cts.Token),
                "untrim" => await TrimOrUntrim(keys, args, rest, trim: false, cts.Token),
                "verify" => await Verify(keys, args, rest, cts.Token),
                "compress" => await CompressOrDecompress(keys, args, rest, compress: true, cts.Token),
                "decompress" => await CompressOrDecompress(keys, args, rest, compress: false, cts.Token),
                _ => throw new UsageException($"Unknown command '{cmd}'."),
            };
        }
        catch (UsageException ex)
        {
            Console.Error.WriteLine("error: " + ex.Message);
            Console.Error.WriteLine("Run '3ds-kit --help' for usage.");
            return 1;
        }
        catch (MissingKeyException ex)
        {
            Console.Error.WriteLine($"\nmissing key: {ex.Message}");
            return 2;
        }
        catch (Exception ex) when (ex is CtrFormatException or IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine("\nerror: " + ex.Message);
            return 1;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("\ncancelled");
            return 130;
        }
    }

    // ------------------------------------------------------------ keys ---

    private static CtrKeyStore LoadKeys(Args args)
    {
        var ks = KeyLocator.LoadDefault(out var errors, args.All("--keys-dir"));
        foreach (var e in errors) Console.Error.WriteLine("warning: " + e);
        bool allowUnknown = args.Has("--allow-unknown-boot9");
        if (args.Value("--boot9") is { } b9) ks.LoadBoot9File(b9, requireKnownHash: !allowUnknown);
        if (args.Value("--aes-keys") is { } aes) ks.LoadAesKeysFile(aes);
        if (args.Value("--seeddb") is { } sdb) ks.LoadSeedDbFile(sdb);
        if (args.Value("--certs-from") is { } certs) ks.LoadCertificateChainFromCia(certs);
        return ks;
    }

    private static int ShowKeys(CtrKeyStore keys)
    {
        var s = keys.GetStatus();
        static string Y(bool b) => b ? "yes" : "NO";
        Console.WriteLine($"NCCH original KeyX (0x2C):  {Y(s.HasNcchOriginalKeyX)}");
        Console.WriteLine($"NCCH 7.x KeyX (0x25):       {Y(s.HasNcch70KeyX)}");
        Console.WriteLine($"NCCH 9.3 KeyX (0x18):       {Y(s.HasNcch93KeyX)}");
        Console.WriteLine($"NCCH 9.6 KeyX (0x1B):       {Y(s.HasNcch96KeyX)}");
        Console.WriteLine($"Common KeyX (0x3D):         {Y(s.HasCommonKeyX)}");
        Console.WriteLine($"Common KeyY count:          {s.CommonKeyYCount}/6");
        Console.WriteLine($"Fixed system key:           {Y(s.HasFixedSystemKey)}");
        Console.WriteLine($"Seeds:                      {s.SeedCount}");
        Console.WriteLine($"Certificate chain:          {Y(keys.CertificateChain is not null)}");
        Console.WriteLine($"Retail ready:               {Y(s.IsRetailReady)}");
        Console.WriteLine("Loaded from:");
        foreach (var f in s.LoadedFrom) Console.WriteLine("  " + f);
        if (s.LoadedFrom.Count == 0)
        {
            Console.WriteLine("  (nothing) - searched:");
            foreach (var d in KeyLocator.CandidateDirectories()) Console.WriteLine("    " + d);
        }
        return 0;
    }

    // ------------------------------------------------------------ info ---

    private static int Info(CtrKeyStore keys, string path)
    {
        var i = CtrInspector.Inspect(path, keys);
        Console.WriteLine($"File:          {i.Path}");
        Console.WriteLine($"Type:          {i.Type}");
        Console.WriteLine($"Size:          {i.FileSize:N0} bytes{(i.Compressed ? " (Z3DS-compressed; size of the file it holds)" : "")}");
        if (i.Type == CtrFileType.Unknown) return 1;
        Console.WriteLine($"Title ID:      {i.TitleIdHex}");
        Console.WriteLine($"Product code:  {i.ProductCode} ({i.Region ?? "unknown region"})");
        Console.WriteLine($"Title version: {i.TitleVersion}");
        if (i.Titles is { } t)
        {
            Console.WriteLine($"Title:         {t.ShortTitle}");
            Console.WriteLine($"Long title:    {t.LongTitle}");
            Console.WriteLine($"Publisher:     {t.Publisher}");
        }
        Console.WriteLine($"Save size:     {i.SaveDataSize:N0} bytes");
        Console.WriteLine($"Encrypted:     {i.Encrypted}");
        if (i.Type == CtrFileType.Cci)
        {
            Console.WriteLine($"Media:         {i.MediaType}, card size {i.MediaSize:N0}, used {i.UsedSize:N0}, {(i.IsTrimmed ? "trimmed" : "untrimmed")}");
        }
        Console.WriteLine("NCCH:");
        foreach (var n in i.Ncchs)
        {
            string can = n.CanDecrypt ? "" : $"  [cannot decrypt: missing {n.MissingKey}]";
            Console.WriteLine($"  [{n.Index}] {n.Role,-28} {n.Size,14:N0}  {n.ProductCode,-12} {n.Crypto}{can}");
        }
        foreach (var note in i.Notes) Console.WriteLine("note: " + note);
        return 0;
    }

    // ------------------------------------------------------ operations ---

    private static async Task<int> Decrypt(CtrKeyStore keys, Args args, List<string> rest, CancellationToken ct)
    {
        Require(rest, 1, "decrypt <in> [out]");
        string input = rest[0];
        bool compress = args.Has("--compress");
        // A plain file keeps its extension, a Z3DS one gets its plain one back, unless --compress asks for Z3DS.
        var type = Directory.Exists(input) ? CtrFileType.Cia : CtrFile.Detect(input);
        string ext = compress ? Z3dsFile.CompressedExtension(type)
            : Directory.Exists(input) ? ".cia"
            : CtrFile.IsCompressed(input) ? Z3dsFile.PlainExtension(type) : Path.GetExtension(input);
        string output = rest.Count > 1 ? rest[1] : Sibling(input, ".decrypted" + ext);
        var r = await new CtrConverter(keys).DecryptAsync(input, output, new CtrConvertOptions
        {
            Overwrite = args.Has("--overwrite"),
            VerifyContents = !args.Has("--no-verify-contents"),
            MatchTicketVersionToTmd = args.Has("--match-ticket-version"),
            Compress = compress,
            CompressionLevel = Level(args),
        }, new ConsoleProgress(), ct);
        return Report(r);
    }

    private static async Task<int> Convert(CtrKeyStore keys, Args args, List<string> rest, CancellationToken ct)
    {
        Require(rest, 1, "convert <in> --to cci|cia [out]");
        string to = (args.Value("--to") ?? throw new UsageException("convert needs --to cci or --to cia")).ToLowerInvariant();
        var target = to switch
        {
            "cci" or "3ds" => CtrOutputFormat.Cci,
            "cia" => CtrOutputFormat.Cia,
            _ => throw new UsageException("--to must be cci or cia"),
        };
        string input = rest[0];
        bool compress = args.Has("--compress");
        string ext = (target, compress) switch
        {
            (CtrOutputFormat.Cci, false) => ".3ds",
            (CtrOutputFormat.Cci, true) => ".zcci",
            (_, false) => ".cia",
            _ => ".zcia",
        };
        string output = rest.Count > 1 ? rest[1] : Sibling(input, ext);
        if (string.Equals(Path.GetFullPath(output), Path.GetFullPath(input),
                OperatingSystem.IsLinux() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase)) output = Sibling(input, ".converted" + ext);
        var options = new CtrConvertOptions
        {
            Decrypt = !args.Has("--keep-encryption"),
            Trim = !args.Has("--no-trim"),
            Overwrite = args.Has("--overwrite"),
            VerifyContents = !args.Has("--no-verify-contents"),
            MatchTicketVersionToTmd = args.Has("--match-ticket-version"),
            Compress = compress,
            CompressionLevel = Level(args),
        };
        var r = await new CtrConverter(keys).ConvertAsync(input, output, target, options, new ConsoleProgress(), ct);
        return Report(r);
    }

    private static async Task<int> TrimOrUntrim(CtrKeyStore keys, Args args, List<string> rest, bool trim, CancellationToken ct)
    {
        Require(rest, 1, (trim ? "trim" : "untrim") + " <in> [out]");
        string input = rest[0];
        string output = rest.Count > 1 ? rest[1] : Sibling(input, (trim ? ".trim" : ".untrim") + Path.GetExtension(input));
        var conv = new CtrConverter(keys);
        var options = new CtrConvertOptions { Overwrite = args.Has("--overwrite") };
        var r = trim
            ? await conv.TrimAsync(input, output, options, new ConsoleProgress(), ct)
            : await conv.UntrimAsync(input, output, options, new ConsoleProgress(), ct);
        return Report(r);
    }

    private static async Task<int> Verify(CtrKeyStore keys, Args args, List<string> rest, CancellationToken ct)
    {
        Require(rest, 1, "verify <file|dir>...");
        var verifier = new CtrVerifier(keys);
        var options = new CtrVerifyOptions { CheckIntegrity = !args.Has("--no-integrity") };
        int worst = 0;
        foreach (var file in ExpandFiles(rest, args.Has("--recursive")))
        {
            var r = await verifier.VerifyAsync(file, options, new ConsoleProgress(), ct);
            ConsoleProgress.Clear();
            Console.WriteLine($"{r.Verdict,-8} {Path.GetFileName(file)}");
            Console.WriteLine($"    {r.Hashes}");
            foreach (var c in r.Checks.Where(c => c.Status != CheckStatus.Pass)) Console.WriteLine($"    {c}");
            int passed = r.Checks.Count(c => c.Status == CheckStatus.Pass);
            if (passed > 0) Console.WriteLine($"    {passed} internal hash check(s) passed");
            if (r.Verdict == CtrVerdict.Bad) worst = 3;
        }
        return worst;
    }

    // ----------------------------------------------------------- helpers ---

    /// <summary>Files given directly, plus files in given folders with a 3DS extension.</summary>
    private static IEnumerable<string> ExpandFiles(IEnumerable<string> inputs, bool recursive)
    {
        foreach (var p in inputs)
        {
            if (Directory.Exists(p))
                foreach (var f in Directory.EnumerateFiles(p, "*", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly)
                             .Where(f => CtrFile.Extensions.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase))
                             .OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
                    yield return f;
            else if (File.Exists(p))
                yield return p;
            else
                throw new UsageException($"Not found: {p}");
        }
    }

    private static async Task<int> CompressOrDecompress(CtrKeyStore keys, Args args, List<string> rest, bool compress, CancellationToken ct)
    {
        Require(rest, 1, (compress ? "compress" : "decompress") + " <in> [out]");
        string input = rest[0];
        var type = CtrFile.Detect(input);
        string output = rest.Count > 1 ? rest[1]
            : Sibling(input, compress ? Z3dsFile.CompressedExtension(type) : Z3dsFile.PlainExtension(type));
        var conv = new CtrConverter(keys);
        var options = new CtrConvertOptions { Overwrite = args.Has("--overwrite"), CompressionLevel = Level(args) };
        var r = compress
            ? await conv.CompressAsync(input, output, options, new ConsoleProgress(), ct)
            : await conv.DecompressAsync(input, output, options, new ConsoleProgress(), ct);
        if (compress)
        {
            long before = new FileInfo(input).Length, after = new FileInfo(r.OutputPath).Length;
            Console.WriteLine($"{before:N0} → {after:N0} bytes ({(before == 0 ? 0 : 100.0 * after / before):0.0}%)");
        }
        return Report(r);
    }

    private static int Level(Args args) =>
        args.Value("--level") is { } l ? int.TryParse(l, out var n) && n is >= 1 and <= 22 ? n : throw new UsageException("--level must be 1 to 22") : 3;

    private static string Sibling(string input, string suffixWithExt)
    {
        string dir = Path.GetDirectoryName(Path.GetFullPath(input)) ?? ".";
        return Path.Combine(dir, Path.GetFileNameWithoutExtension(input) + suffixWithExt);
    }

    private static List<string> Require(List<string> rest, int count, string usage)
    {
        if (rest.Count < count) throw new UsageException("usage: 3ds-kit " + usage);
        return rest;
    }

    private static int Report(CtrOperationResult r)
    {
        ConsoleProgress.Clear();
        Console.WriteLine($"Wrote {r.OutputPath} ({r.OutputType}{(r.Compressed ? ", Z3DS" : "")})");
        if (r.OutputHashes is { } h) Console.WriteLine($"    {h}");
        foreach (var w in r.Warnings) Console.WriteLine("warning: " + w);
        return 0;
    }
}

internal sealed class UsageException : Exception
{
    public UsageException(string message) : base(message) { }
}

/// <summary>Synchronous progress printer (Progress&lt;T&gt; would post callbacks out of order).</summary>
internal sealed class ConsoleProgress : IProgress<OperationProgress>
{
    private static readonly object Gate = new();

    public void Report(OperationProgress value)
    {
        if (Console.IsOutputRedirected) return;
        lock (Gate)
        {
            string line = $"{value.Stage}: {value.Fraction * 100,5:0.0}%";
            if (line.Length > 78) line = line[..78];
            Console.Write("\r" + line.PadRight(78));
        }
    }

    public static void Clear()
    {
        if (Console.IsOutputRedirected) return;
        lock (Gate) Console.Write("\r" + new string(' ', 78) + "\r");
    }
}

/// <summary>Minimal argument parser: "--flag", "--name value" (repeatable), and positionals.</summary>
internal sealed class Args
{
    private static readonly HashSet<string> ValueOptions = new(StringComparer.Ordinal)
    {
        "--keys-dir", "--boot9", "--aes-keys", "--seeddb", "--certs-from", "--to", "--level",
    };

    private readonly List<(string Name, string? Value)> _options = new();
    public List<string> Positionals { get; } = new();

    public Args(string[] argv)
    {
        for (int i = 0; i < argv.Length; i++)
        {
            string a = argv[i];
            if (a.StartsWith("--", StringComparison.Ordinal) || a == "-h")
            {
                int eq = a.IndexOf('=');
                if (eq > 0) { _options.Add((a[..eq], a[(eq + 1)..])); continue; }
                if (ValueOptions.Contains(a))
                {
                    if (i + 1 >= argv.Length) throw new UsageException($"{a} needs a value");
                    _options.Add((a, argv[++i]));
                }
                else _options.Add((a, null));
            }
            else Positionals.Add(a);
        }
    }

    public bool Has(string name) => _options.Any(o => o.Name == name);
    public string? Value(string name) => _options.LastOrDefault(o => o.Name == name).Value;
    public IEnumerable<string> All(string name) => _options.Where(o => o.Name == name && o.Value is not null).Select(o => o.Value!);
}
