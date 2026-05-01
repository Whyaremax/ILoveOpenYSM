# ILoveOpenYSM

ILoveOpenYSM is an open YSM extractor for Yes Steve Model files. It is packaged as a small offline Python tool for inspecting and extracting YSM, YSGP, BOM v3, and Minecraft custom player model assets without depending on the original abandoned NSM/NoSteveModel workflow.

Keywords: YSM extractor, Yes Steve Model extractor, OpenYSM, ILoveOpenYSM, NoSteveModel alternative, NSM alternative, Minecraft YSM decoder, YSGP extractor, BOM v3 extractor, Yes Steve Model tools, Minecraft player model extractor, YSM model converter.

## Release

Current release: `1.0.0`

The 1.0.0 package keeps the user-facing extractor and removes verifier/debug tooling from the public bundle. It is intended for practical offline extraction, not runtime tracing or native debugger workflows.

## What It Supports

- BOM v3 YSM containers, including known format families `1`, `9`, `15`, and `31`.
- Compact YSGP v2 entry listing and optional payload/key dumping.
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

## Project Boundary

This release intentionally excludes verifier scripts, Windows automation, headed client capture helpers, GDB traces, anti-debug experiments, and runtime export harnesses. Those are useful research tools, but they make the release harder to use and easier to misunderstand.

ILoveOpenYSM 1.0.0 is the extractor-only package.

## Disclaimer Of Liability

This software is provided for research, interoperability, archival, and personal data recovery use. It is provided "as is", without warranty of any kind. The authors and contributors are not liable for data loss, account issues, game/mod compatibility problems, copyright misuse, service violations, damages, or any other liability arising from use of this software.

You are responsible for making sure you have the right to extract, inspect, convert, or redistribute any model, texture, animation, or other asset you process with this tool.

## License

ILoveOpenYSM is released under the MIT License. See [LICENSE](LICENSE).
