# ILoveOpenYSM

ILoveOpenYSM is an open YSM extractor for Yes Steve Model files. It is packaged as a small offline Python tool for inspecting and extracting YSM, YSGP, and BOM v3 containers. The workflow was inspired by the older NSM/NoSteveModel approach, but this repository is maintained as an independent project.

Keywords: YSM extractor, Yes Steve Model extractor, OpenYSM, ILoveOpenYSM, NoSteveModel alternative, NSM alternative, Minecraft YSM decoder, YSGP extractor, BOM v3 extractor, Yes Steve Model tools, Minecraft player model extractor, YSM model converter.

## Unofficial project notice

This project is not affiliated with, endorsed by, maintained by, or connected to the official Yes Steve Model project, the YSM/CIT Resewn team site, or the Modrinth Yes Steve Model page:

- https://ysm.cfpa.team/
- https://modrinth.com/mod/yes-steve-model

This repository exists only as an independent extractor, interoperability, and research project.

## Free project notice

ILoveOpenYSM is free and open source. Do not pay for any third-party service or tool that claims to sell this project as a paid OpenYSM extractor.

## Release

Current release: `1.0.0`

The `1.0.0` package keeps the user-facing extractor and removes verifier/debug tooling from the public bundle. It is intended for practical offline extraction, not runtime tracing or native debugger workflows.

## What it supports

- BOM v3 YSM containers, including known format families `Legacy`, `1`, `9`, `15`, and `31`.
- Format `31` currently works best because of its simplified structure.
- Format `15` is still a work in progress, but it is very close to being supported.
- Legacy `<1.1.5` YSGP files are still not fully covered, although they appear to be the easiest remaining format family.
- Asset scanning and folder export through `--scan-assets`, `--dump-assets`, and `--dump-folder`.
- Optional source-oracle restore for cases where matching original authored files are available nearby. (In another word; why you need it when you have original file)

## Quick start

```bash
python3 ysm_extract.py --help
python3 ysm_extract.py --dump-folder path/to/model.ysm
```

`ysm_extract.py` is the supported entrypoint.

`ysm_extractor.py` is included as a compatibility alias for the same CLI.

Run the root scripts from this folder. Directly invoking files under `extractors/` is not the stable public interface.

## Common commands

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

## How it works

The extractor workflow can be summarized as follows:

1. Check the metadata and the first few bytes of the binary to confirm whether the file is a valid YSM model.
2. Identify the format version from the metadata.
3. Identify the key from the first few bytes.
4. Use the known offset rules to decode the remaining binary with the key.
5. Output the decoded data as Zstandard data.
6. Unpack the Zstandard data.
7. Route the decoded content to the correct format-specific extractor.

For newer formats above `15`, especially format `31`, the decoded content is closer to a folder-like structure and can usually be dumped more cleanly. This appears to be because newer formats no longer lower everything into the older compact binary structure. That design change likely made the format easier to maintain and reduced the need for heavy binary lowering.

For formats `15` and below, extraction is harder. After the Zstandard stage, the extractor has to infer model cube data from construction patterns, boundaries, and layout guesses. This is why format `15` is currently treated as the hardest known family. Format `9` appears to be a simplified version of that older structure.

## Future plans

- Add fuller support for all known versions.
- Keep the extractor maintained for future format changes.
- Improve recovery accuracy for older binary-lowered formats.

## Project boundary

ILoveOpenYSM is an extractor-only package. It is not a replacement for the original mod, and it does not provide the original native runtime capability.

## Communication

- Discord: `nooboyeah`
- Discord server invite: https://discord.gg/h6Gy9EgcWj
- No QQ contact is provided.
- No additional contact channels are provided.

## Disclaimer of liability

This software is provided for research, interoperability, archival, and personal data recovery use. It is provided "as is", without warranty of any kind. The authors and contributors are not liable for data loss, account issues, game/mod compatibility problems, copyright misuse, service violations, damages, or any other liability arising from use of this software.

**You are responsible for making sure you have the right** to extract, inspect, convert, or redistribute any model, texture, animation, or other asset you process with this tool.

## License

ILoveOpenYSM is released under the MIT License. See [LICENSE](LICENSE).
