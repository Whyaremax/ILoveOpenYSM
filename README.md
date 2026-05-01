# ILoveOpenYSM

ILoveOpenYSM is an open YSM extractor for Yes Steve Model files. It is packaged as a small offline Python tool for inspecting and extracting YSM, YSGP, BOM v3. This is inspired on the original abandoned NSM/NoSteveModel workflow.

Keywords: YSM extractor, Yes Steve Model extractor, OpenYSM, ILoveOpenYSM, NoSteveModel alternative, NSM alternative, Minecraft YSM decoder, YSGP extractor, BOM v3 extractor, Yes Steve Model tools, Minecraft player model extractor, YSM model converter.

# ANY paided OpenYSM extractor is a scam, this is a free project open and available for anyone.

## Release

Current release: `1.0.0`

The 1.0.0 package keeps the user-facing extractor and removes verifier/debug tooling from the public bundle. It is intended for practical offline extraction, not runtime tracing or native debugger workflows.

## What It Supports

- BOM v3 YSM containers, including known format families `Legacy`, `1`, `9`, `15`, and `31`.
- Among them, `31` works the best due to simpilifed structure, `15` are working in progress, with very being close to done.
- Legacy `<1.1.5 YSGP` are still uncovered, although its the easiest.
- Asset scanning and folder export through `--scan-assets`, `--dump-assets`, and `--dump-folder`.
- Optional source-oracle restore for cases where matching original authored files are available nearby.

## Quick Start

```bash
python3 ysm_extract.py --help
python3 ysm_extract.py --dump-folder path/to/model.ysm
```

`ysm_extract.py` is the supported entrypoint.

`ysm_extractor.py` is included as a compatibility alias for the same CLI.

Run the root scripts from this folder. Directly invoking files under `extractors/` is not the stable public interface.

## Common Commands

```bash
python3 ysm_extract.py --scan-assets path/to/model.ysm
python3 ysm_extract.py --dump-assets path/to/model.ysm
python3 ysm_extract.py --dump-decoded path/to/model.ysm
python3 ysm_extract.py --dump-entries path/to/archive.ysgp
```

Interactive mode is available when running from a terminal:

```bash
python3 ysm_extract.py --interactive
```

## How does it work?

The extractor workflow could be simplified to following:
Check for if its valid YSM model from metadata, and first few byte of binary 
Identify format version from metadata
Identify the key within the first few byte
Use preset offset, decrypt the rest of binary with the key, and output as ZSTD
Unpack ZSTD
If > 15 (that's the cut off point I know, there could be a 28 inbetween I remember)
  Treat it as a folder-ish structure and dump everything cleanly. This is because on this verison, file are no longer lowered to binary, where before it lowered to minimal render requirement, making both maintenance and decryption hard, this change is most likely due to maintenance complexity with lowering to binary and unnesscary of doinf so.

If =< 15
  We treat it same way until to unzipping ZTSD part. We need start "guessing" the cubes from how its constructed, patterns, guesses where it end. This causes inaccuracy, this is why format 15, I call by fair hardest version, format 9 seem like a simplified format 15, and so on.

## Future plan

Add full support for all version, and any future version.
**Keep it alive**

## Project Boundary

ILoveOpenYSM is extractor-only package.

## Communication

Discord nooboyeah
Discord server perm link https://discord.gg/h6Gy9EgcWj
No QQ
And I'm not giving out anything else

## Disclaimer Of Liability

This software is provided for research, interoperability, archival, and personal data recovery use. It is provided "as is", without warranty of any kind. The authors and contributors are not liable for data loss, account issues, game/mod compatibility problems, copyright misuse, service violations, damages, or any other liability arising from use of this software.

**You are responsible for making sure you have the right** to extract, inspect, convert, or redistribute any model, texture, animation, or other asset you process with this tool.

## License

ILoveOpenYSM is released under the MIT License. See [LICENSE](LICENSE).
