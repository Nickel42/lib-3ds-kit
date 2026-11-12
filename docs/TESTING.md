# Testing

## 1. Unit tests

```bash
dotnet build
dotnet test
```

The tests run against both library targets (net8.0 and net10.0); CI runs them on Windows, Linux and macOS and builds the Android sample. All tests use fake keys and synthetic files from `tests/fixtures`, whose expected outputs come from the Python reference implementation. If you change the reference logic, regenerate them:

```bash
python3 -I reference/python/gen_fixtures.py tests/fixtures      # needs: pip install cryptography
```

The generator is deterministic (fixed random seed), so the same code always gives the same files on any OS. It also self-checks:
- decrypting gives back the original plaintext
- converted files pass all internal hash checks
- CCI → CIA → CCI preserves the partitions

The CDN tests build CDN folders from the fixture CIA with structurally valid fake certificates.

## 2. Real-file checklist

Run these with the CLI (`3ds-kit`, or `dotnet run --project tools/lib-3ds-kit.Cli -- ...`). Put your `boot9.bin`, `aes_keys.txt` and `seeddb.bin` in your Azahar/Citra `sysdata` folder or `~/.3ds`, or pass `--keys-dir`.

| # | Do | Expect |
|---|---|---|
| 1 | `keys` | "Retail ready: yes" and the files you expect listed |
| 2 | `info` on an encrypted cart dump | Correct title, product code, region, "7.x (0x25)" or "Original (0x2C)" crypto, trimmed/untrimmed state |
| 3 | `verify` an untouched cart dump | `Intact`; all internal checks pass |
| 4 | `decrypt` that dump, then `verify` the output | `Intact` |
| 5 | Boot the decrypted .3ds in Azahar | Runs |
| 6 | `convert --to cia` the cart dump, then install it in Azahar (and FBI on CFW if you like) | Installs and runs; the manual opens from the HOME Menu |
| 7 | `decrypt` an eShop CIA (including a seed-crypto title), then install it in Azahar | Runs |
| 8 | `convert --to cci` an eShop CIA, then boot it in Azahar | Runs; `verify` gives `Intact` |
| 9 | `convert --to cia --keep-encryption`, then `info` | NCCH still encrypted; installs in Azahar |
| 10 | `trim` / `untrim` a dump | Untrimmed size equals the card size; trimming it again gives back the original |
| 11 | Try an update CIA and a DLC CIA with `convert --to cci` | Clear error. `decrypt` still works on them |
| 12 | `convert <cdn-folder> --to cia` on a real CDN download, then install it in Azahar | Installs and runs; contents verified against the TMD |

When something fails, include the CLI output plus `info` output for the input file. `info` prints the encryption type, content layout and any missing key name.

### What has been checked on real files

On 288 eShop, Virtual Console, update and DLC CIAs (original, 7.x, New 3DS 9.6 and seed crypto, with and without the title-key layer):

- `info` opens all of them.
- On a test set covering each kind:
  - `verify` and `decrypt` pass every internal check, and decrypting twice gives the same bytes.
  - CIA → CCI → CIA → CCI returns the same CCI, and trim(untrim) returns the original.
  - `--keep-encryption` keeps each partition's crypto.
  - Updates and DLC give a clear error for CCI.
- CDN folders split from six CIAs rebuild the original CIA byte for byte, and decrypt to the same bytes as decrypting the CIA.
- The Linux build of `3ds-kit` gives byte-identical output to Windows.

Not yet checked: cartridge dumps (items 2–5 and 10), installing or booting in Azahar or on a console, a real (rather than reconstructed) CDN download, and New 3DS 9.3 (0x18) titles.

## 3. Things most likely to need attention

- **Decrypted header flags.** See SPEC.md → Known limitations. If decrypted cartridge dumps from other tools differ, the likely cause is header bytes: NCSD 0x1100 copy flags, or which flags[7] bits get cleared. That is a one-line change in `NcchHeader.ApplyDecryptedFlags` / `CtrConverter.BuildDecryptedCciView`.
- **Console installs of CIAs made from carts.** These need a real certificate chain (`--certs-from some.cia`) and signature patches (Luma3DS).

## Azahar's Z3DS files

`tests/fixtures/azahar/` holds two files Azahar 2123 made itself (`azahar -c`) from the decrypted reference fixtures: `game_a.decrypted.zcci` and `game_b.decrypted.zcia`. `Z3dsTests.ReadsFilesAzaharMade` decompresses them and checks the result against `expected.json`. The other direction was checked by hand: `azahar -x` on files from `3ds-kit compress` gives the original bytes. To refresh them, run `azahar -c <file> -o <folder>` on `expected/game_a.decrypted.3ds` (renamed `.cci`) and `expected/game_b.decrypted.cia`.
