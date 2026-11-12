# lib-3ds-kit

A pure C# library for converting and decrypting Nintendo 3DS files in any .NET app: decrypt CCI (`.3ds`), CIA, CXI and CFA files, convert between CCI and CIA, build CIAs from CDN downloads, trim or untrim cartridge images, and compress or decompress Azahar's Z3DS formats (`.zcci`, `.zcia`, `.zcxi`, `.z3dsx`). It can also read a file's title and encryption details, and check the hashes stored inside it to confirm a result came out intact. No native code, no keys bundled; the only dependency is [ZstdSharp.Port](https://github.com/oleg-st/ZstdSharp), a pure managed zstd.

[![CI](https://github.com/Nickel42/lib-3ds-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/Nickel42/lib-3ds-kit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Nickel42/lib-3ds-kit/blob/main/LICENSE)

| Package | What it is |
|---|---|
| **lib-3ds-kit** | The library (namespace `Lib3dsKit`) |
| **lib-3ds-kit.Cli** | The `3ds-kit` command-line tool, as a `dotnet tool` or a standalone binary |

## Platforms

The library is plain managed code, so the same package works everywhere .NET runs. It targets `net8.0` and `net10.0` and is marked trim- and AOT-compatible.

| Platform | Status |
|---|---|
| Windows (x64, Arm64) | Tested in CI on every change |
| Linux (x64, Arm64) | Tested in CI on every change |
| macOS (Apple silicon, Intel) | Tested in CI on every change |
| Android | An Android app using the library is built (trimmed) in CI on every change |
| iOS, Mac Catalyst, Native AOT | Expected to work (trim/AOT analyzers report no warnings); not tested in CI |

Any app on .NET 8 or later can use it, including `net8.0-android`, `net9.0-ios` and so on. .NET Framework and .NET Standard are not supported.

## Install

```bash
dotnet add package lib-3ds-kit
```

The command-line tool:

```bash
dotnet tool install -g lib-3ds-kit.Cli
```

Standalone `3ds-kit` binaries for Windows, Linux and macOS (no .NET install needed) are attached to each [GitHub release](https://github.com/Nickel42/lib-3ds-kit/releases). Until a release reaches nuget.org, reference `src/lib-3ds-kit` directly or use the packages attached to a release.

## Supported files and operations

| Input | Decrypt | → CCI (.3ds) | → CIA | Trim / untrim | Check hashes |
|---|---|---|---|---|---|
| CCI (.3ds, .cci) | ✓ (stays trimmed/untrimmed) | ✓ decrypt + trim/pad | ✓ | ✓ | ✓ |
| CIA (.cia) | ✓ (title-key + NCCH layers) | ✓ game titles only | — | — | ✓ (TMD hashes) |
| CXI / CFA | ✓ | — | — | — | ✓ |
| CDN folder (`tmd`, `cetk`, content files) | ✓ (→ decrypted CIA) | via the CIA | ✓ | — | contents checked against the TMD |

Every row also takes the file compressed as Azahar's Z3DS (`.zcci`, `.zcia`, `.zcxi`), and every result can be written compressed. See [Azahar's compressed formats](#azahars-compressed-formats-z3ds).

Encryption: original (0x2C), 7.x (0x25), New 3DS 9.3 (0x18) and 9.6 (0x1B), seed crypto (seeddb), fixed zero key and fixed system key, and CIA title keys (common keys 0–5).

Conversions decrypt by default, which is what emulators such as Azahar and custom firmware expect. `Decrypt = false` keeps the encryption and only changes the container.

## Keys

The library ships no keys. Users supply their own, dumped from their own console:

| File | Provides | Where it comes from |
|---|---|---|
| `boot9.bin` (or `boot9_prot.bin`) | KeyX 0x2C and 0x3D | Dumped with GodMode9 |
| `aes_keys.txt` | KeyX 0x25/0x18/0x1B, `common0`–`common5`, optional `fixedSystemKey` | The file Azahar/Citra use |
| `seeddb.bin` | Seeds for seed-encrypted eShop titles | GodMode9 / Azahar |
| a CIA the user owns (optional) | Certificate chain for CCI → CIA | `CtrKeyStore.LoadCertificateChainFromCia` |

`KeyLocator` looks in the folders you pass first, such as your app's own keys folder. After that it checks the usual places: Azahar and Citra `sysdata` folders (Windows, macOS, Linux/XDG), `~/.3ds`, `~/3ds`, and `keys/` next to the executable. `boot9.bin` is checked against the SHA-256 of a retail dump, and `KeyStoreStatus.IsRetailReady` says whether typical cartridges and eShop CIAs will work.

## Quick start

These snippets come from [`samples/QuickStart`](https://github.com/Nickel42/lib-3ds-kit/tree/main/samples/QuickStart), which CI compiles on every change.

```csharp
using Lib3dsKit;
using Lib3dsKit.IO;
using Lib3dsKit.Keys;
using Lib3dsKit.Ncch;
using Lib3dsKit.Operations;
using Lib3dsKit.Verification;

// Load keys: the folders you pass are searched first, then Azahar/Citra and ~/.3ds.
var keys = KeyLocator.LoadDefault(out var errors, extraDirectories: [keysFolder]);
Console.WriteLine($"Retail ready: {keys.GetStatus().IsRetailReady}");

// Inspect (reads headers only).
CtrFileInfo info = CtrInspector.Inspect(path, keys);
Console.WriteLine($"{info.Titles?.ShortTitle} [{info.ProductCode}] {info.Region}");

// Convert: a .3ds, a .cia or a CDN folder → a decrypted CIA (CtrOutputFormat.Cci for a .3ds).
var converter = new CtrConverter(keys);
var progress = new Progress<OperationProgress>(p => Console.Write($"\r{p.Stage}: {p.Fraction:P0}"));
try
{
    CtrOperationResult result = await converter.ConvertAsync(input, output, CtrOutputFormat.Cia,
        new CtrConvertOptions(), progress, cancellationToken);
    foreach (var warning in result.Warnings) Console.WriteLine(warning);
}
catch (MissingKeyException ex) { Console.WriteLine($"Missing key: {ex.KeyName}"); } // e.g. "common1", "seed:0004000000123400"
catch (CtrFormatException ex) { Console.WriteLine(ex.Message); }

// Check the result's internal hashes.
CtrVerifyReport report = await new CtrVerifier(keys).VerifyAsync(output);
// report.Verdict: Intact / Unknown (checks skipped, e.g. missing keys) / Bad
```

Other operations: `DecryptAsync`, `TrimAsync`, `UntrimAsync`, `CompressAsync`, `DecompressAsync`. All have synchronous versions too.

## Azahar's compressed formats (Z3DS)

`.zcci`, `.zcia`, `.zcxi` and `.z3dsx` are Azahar's compressed versions of `.cci`, `.cia`, `.cxi` and `.3dsx`: zstd in the seekable format, so Azahar plays them without unpacking. A decrypted game typically shrinks by a third to a half.

- **Every operation reads them:** decrypt a `.zcci`, convert a `.zcia` to a CCI, inspect or verify one. Only the parts read are decompressed, and no temporary file is made.
- **Write one from any operation** with `Compress = true`:

  ```csharp
  // An encrypted .cia → a decrypted, compressed .zcci, in one pass.
  await converter.ConvertAsync("game.cia", "game.zcci", CtrOutputFormat.Cci, new CtrConvertOptions { Compress = true });
  ```
- **Or as they are:** `CompressAsync` (nothing is decrypted) and `DecompressAsync` (byte for byte).
- **Hashes:** `OutputHashes` are those of the plain file, so they match the No-Intro DAT entry of the decrypted dump even when the file is compressed. `CtrVerifier` likewise hashes what a compressed file holds.
- **Not supported:** Azahar's bundles (`.bcci`, `.bcia`, `.bcxi`).

## Using it in an app

- **Threads:** the async methods run on the thread pool. In WPF, WinForms, Avalonia or MAUI, await them from the UI thread and create `Progress<T>` there, so progress reports arrive on the UI thread. Reports come at most every 8 MiB.
- **Safe output:** every operation writes to `<output>.lib-3ds-kit.tmp` and moves it into place only on success. Cancelling or failing leaves no partial file. Existing files are never overwritten unless `Overwrite = true`.
- **Memory:** a few MiB, whatever the file size; everything streams.
- **File pickers:** `CtrFile.Extensions` lists the extensions. `CtrFile.Detect` sniffs the content, so misnamed files still work.
- **Android and iOS:** the APIs take file paths. Files picked through the Storage Access Framework (Android) or document picker (iOS) arrive as streams or content URIs; copy them into your app's cache folder first. On Android, pass your app's files folder to `KeyLocator.LoadDefault` as the key folder (see [`samples/AndroidSmoke`](https://github.com/Nickel42/lib-3ds-kit/tree/main/samples/AndroidSmoke)).

## CDN folders

Pass a folder as the input to `ConvertAsync(..., CtrOutputFormat.Cia)` or `DecryptAsync`:

- **Names:** raw CDN names (`tmd`, `cetk`, `00000000`) and NUSspli-style names (`title.tmd`, `title.tik`, `title.cert`, `00000000.app`) both work. With several `tmd.<version>` files, the highest is used.
- **Certificates:** the ones Nintendo appends to the TMD and ticket become the CIA's certificate chain.
- **Verification:** every content is checked against its TMD SHA-256 before anything is written (`VerifyContents`).
- **DLC:** a DLC folder may hold only some of its contents. Other titles must be complete.
- **Title-version mismatch:** a ticket whose title version differs from the TMD's, which is common in CDN downloads, is reported. `MatchTicketVersionToTmd` writes a matching one.
- **CCI:** CDN folders convert to CIA only. Convert that CIA to CCI afterwards.

## Checking a file

`CtrVerifier` hashes a file (CRC32, MD5, SHA-1, SHA-256) and checks the hashes stored inside it:

- **CIA:** the TMD SHA-256 of every content.
- **NCCH:** the extended header, logo, ExeFS superblock, every ExeFS file and the RomFS superblock.

The verdict is `Intact` when every check passes, `Bad` when any fails, and `Unknown` when the checks could not run (for example, missing keys for an encrypted file). Run it after a conversion to confirm the output is sound.

## Command line (`3ds-kit`)

```bash
3ds-kit keys
3ds-kit info "Game.3ds"
3ds-kit decrypt "Game.3ds"                      # -> Game.decrypted.3ds
3ds-kit convert "Game.3ds" --to cia
3ds-kit convert "Game.cia" --to cci --no-trim
3ds-kit convert "cdn/0004000000123400" --to cia # CDN folder -> decrypted CIA
3ds-kit trim "Game.3ds"
3ds-kit verify "Game.cia"                       # or a folder; add --recursive
3ds-kit convert "Game.cia" --to cci --compress   # -> Game.zcci, decrypted and compressed for Azahar
3ds-kit compress "Game.3ds"                     # -> Game.zcci, as it is
3ds-kit decompress "Game.zcci"                  # -> Game.cci
```

Run `3ds-kit --help` for every option (`--keys-dir`, `--boot9`, `--aes-keys`, `--seeddb`, `--certs-from`, `--keep-encryption`, `--compress`, `--level`, `--match-ticket-version`, …).

## Building from source

Needs the .NET 10 SDK (the tests also run on .NET 8 if it is installed).

```bash
dotnet build
dotnet test
dotnet pack -c Release -o artifacts
```

The tests use fake keys and synthetic files, so they run anywhere. See [docs/TESTING.md](https://github.com/Nickel42/lib-3ds-kit/blob/main/docs/TESTING.md) for testing with real files and [docs/SPEC.md](https://github.com/Nickel42/lib-3ds-kit/blob/main/docs/SPEC.md) for byte layouts, design decisions and known limitations. Releases are described in [CONTRIBUTING.md](https://github.com/Nickel42/lib-3ds-kit/blob/main/CONTRIBUTING.md).

## Legal

This library is for working with files you dumped from hardware and software you own. It contains no Nintendo keys, certificates or other copyrighted Nintendo material; the test fixtures use randomly generated fake keys. Format details come from public documentation and other open-source projects; see [THIRD_PARTY_NOTICES.md](https://github.com/Nickel42/lib-3ds-kit/blob/main/THIRD_PARTY_NOTICES.md). "Nintendo 3DS" is a trademark of Nintendo; this project is not affiliated with or endorsed by Nintendo.

## License

[MIT](https://github.com/Nickel42/lib-3ds-kit/blob/main/LICENSE) © 2026 Nickel42
