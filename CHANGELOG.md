# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/); while the version is 0.x, minor versions may change the API.

## Unreleased

### Added
- **Azahar's compressed formats (Z3DS):** `.zcci`, `.zcia`, `.zcxi` and `.z3dsx`.
  - **Reading:** every operation takes a compressed file as input. `CtrFile.OpenRead` decompresses as it reads, frame by frame, so decrypting a `.zcci` or converting a `.zcia` to a CCI needs no extra step and no temporary file.
  - **Writing:** `CtrConvertOptions.Compress` writes any result as Z3DS, with `CompressionLevel` (default 3, as Azahar) and `CompressionFrameSize` (default Azahar's: 256 KiB, or 32 MiB for a CIA). `CompressAsync`/`DecompressAsync` compress a file as it is, or decompress one byte for byte. `OutputHashes` are always those of the plain result, so they can be checked against a DAT.
  - **Inspecting:** `CtrFile.IsCompressed`, `CtrFileInfo.Compressed`, and `Z3dsFile` and `Z3dsReadStream` for the header, metadata and frames.
  - **CLI:** new `compress` and `decompress` commands, `--compress` and `--level` for `decrypt` and `convert`, and every command reads Z3DS input.
- **Dependency:** [ZstdSharp.Port](https://github.com/oleg-st/ZstdSharp) (MIT, pure managed zstd). The library is still pure managed code.

### Changed (breaking)
- **`CtrFile.OpenRead` returns a `Stream`,** a `Z3dsReadStream` for a compressed file, rather than a `FileStream`.

### Changed (breaking)
- **Renamed to `lib-3ds-kit`:** the repository is now [Nickel42/lib-3ds-kit](https://github.com/Nickel42/lib-3ds-kit), the packages are `lib-3ds-kit` and `lib-3ds-kit.Cli`, and release downloads are named `lib-3ds-kit-cli-<version>-<platform>`. The namespace is now `Lib3dsKit` (was `ThreeDsCiaLibrary`; sub-namespaces such as `Lib3dsKit.IO`, `.Crypto` and `.Hashing` follow), and the command-line tool is now `3ds-kit` (was `3ds`; the binaries are `3ds-kit.dll`/`3ds-kit.exe`).
- **Temporary output files** are named `<output>.lib-3ds-kit.tmp` (was `<output>.3ds-cia-library.tmp`).

## 0.11.0

The library is now a single standalone package focused on converting and decrypting 3DS files.

### Changed (breaking)
- **One package:** `3ds-cia-library` (namespace `ThreeDsCiaLibrary`). The stream, crypto and hashing helpers are part of it now, under `ThreeDsCiaLibrary.IO`, `.Crypto` and `.Hashing`.
- **The command-line tool is `3ds`** (package `3ds-cia-library.Cli`). Release downloads are named `3ds-cia-library-cli-<version>-<platform>`.
- **`CtrVerifier` checks internal hashes only.** The constructor takes just the key store, and the verdicts are `Intact`, `Unknown` and `Bad`.
- **`KeyLocator`** no longer adds an app-specific keys folder; pass your app's folder through `extraDirectories`.
- **Temporary output files** are named `<output>.3ds-cia-library.tmp`.

### Removed
- DAT support (Logiqx/ClrMamePro parsing, hash and serial lookup), DAT-based verification verdicts and the padded "untrimmed" hash, and file renaming, including the CLI's `rename` command and `--dat` option.

### Other
- Test fixtures regenerated with neutral fake publisher names; the generator now writes identical files on every OS.

## 0.10.0

### Added
- **CDN → CIA.** Pass a CDN folder (`tmd`, `cetk` and content files, or NUSspli-style names) to `ConvertAsync(..., CtrOutputFormat.Cia)` or `DecryptAsync`, or to the CLI's `convert` and `decrypt`. Contents are verified against the TMD before writing (`VerifyContents`), partial DLC is allowed, and ticket/TMD title-version mismatches are reported (`MatchTicketVersionToTmd` fixes them).
- **Packaging:** NuGet packages targeting `net8.0` and `net10.0`, marked trim- and AOT-compatible, with source link and symbol packages.
- **Command-line tool:** installable as a `dotnet tool`; standalone binaries for Windows, Linux and macOS (x64 and Arm64) come with each release.
- **CI:** tests on Windows, Linux and macOS (.NET 8 and .NET 10), plus a trimmed Android app build.
- Samples: `QuickStart` (the README's code) and `AndroidSmoke`.

### Fixed
- Region detection for DLC and update product codes with a suffix (e.g. `CTR-M-AXCE-00` now gives USA instead of unknown).
- CIA output (decrypting a CIA, CCI → CIA) reports progress while it hashes the result, instead of sitting at 100%. `MultiHasher.HashStream` takes an optional `ProgressTracker`.

### Changed
- Licensed under MIT.

## 0.9.0-rc1

First release candidate: decryption of CCI, CIA, CXI and CFA (all retail crypto types and seeds), CCI ↔ CIA conversion, trim/untrim, inspection, and a command-line test harness.
