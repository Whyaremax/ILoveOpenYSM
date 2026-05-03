# ILoveOpenYSM

ILoveOpenYSM is a free, open-source, offline YSM extractor for Yes Steve Model files. It is designed for inspecting and extracting YSM, YSGP, and BOM v3 containers without relying on the original native runtime.

The workflow was inspired by the older NSM/NoSteveModel approach, but this repository is maintained as an independent project.

> [!IMPORTANT]
> ILoveOpenYSM is not affiliated with, endorsed by, maintained by, or connected to the official Yes Steve Model project, the YSM/CIT Resewn team site, or the Modrinth Yes Steve Model page.
>
> Official/project pages this repository is **not** related to:
>
> - https://ysm.cfpa.team/
> - https://modrinth.com/mod/yes-steve-model

> [!NOTE]
> This project exists as an independent extractor, interoperability, archival, and research tool. It is not a replacement for the original mod.

Keywords: YSM extractor, Yes Steve Model extractor, OpenYSM, ILoveOpenYSM, NoSteveModel alternative, NSM alternative, Minecraft YSM decoder, YSGP extractor, BOM v3 extractor, Yes Steve Model tools, Minecraft player model extractor, YSM model converter.

## Project status

Current release: `1.0.0`

The `1.0.0` package keeps the user-facing extractor and removes verifier/debug tooling from the public bundle. It is intended for practical offline extraction, not runtime tracing or native debugger workflows.

> [!TIP]
> For most users, start with `ysm_extract.py --dump-folder path/to/model.ysm`.

> [!WARNING]
> Do not pay for any third-party service or tool that claims to sell this project as a paid OpenYSM extractor. ILoveOpenYSM is free and open source.

## What this project is

- A small offline Python extractor for YSM-related containers.
- A research and interoperability tool for understanding YSM/YSGP/BOM v3 files.
- A practical exporter for supported model assets, especially format `31`.
- A public, free alternative to abandoned or closed extractor workflows.

## What this project is not

- It is not the official Yes Steve Model project.
- It is not connected to `ysm.cfpa.team` or the Modrinth Yes Steve Model page.
- It is not a replacement for the original mod.
- It does not provide the original native runtime capability.
- It does not guarantee official/native export parity for every legacy format.

## What it supports

- BOM v3 YSM containers, including known format families `Legacy`, `1`, `9`, `15`, and `31`.
- Format `31` currently works best because of its simplified structure.
- Format `15` is still a work in progress, but it is very close to being supported.
- Legacy `<1.1.5` YSGP files are still not fully covered, although they appear to be the easiest remaining format family.
- Asset scanning and folder export through `--scan-assets`, `--dump-assets`, and `--dump-folder`.
- Optional source-oracle restore for cases where matching original authored files are available nearby.

> [!CAUTION]
> Legacy formats can require heuristic reconstruction. Output from formats `1`, `9`, and `15` may differ from official native export output.

## Quick start

```bash
python3 ysm_extract.py --help
python3 ysm_extract.py --dump-folder path/to/model.ysm
```

`ysm_extract.py` is the supported entrypoint.

`ysm_extractor.py` is included as a compatibility alias for the same CLI.

> [!IMPORTANT]
> Run the root scripts from this folder. Directly invoking files under `extractors/` is not the stable public interface.

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

1. `ysm_extract.py` bootstraps the local extractor package and forwards execution to `extractors/ysm_extract.py`.
2. The main extractor detects the container type from the file header:
   - BOM v3 containers start with UTF-8 BOM + `YSGP`.
   - Compact YSGP containers start with `YSGP` and use a big-endian version field.
3. For BOM v3 containers, the extractor reads the text property block and uses the `<format>` field to identify the codec format.
4. The outer v3 parser validates the wrapper layout, including the property block end, separator byte, outer version `3`, and trailing hash.
5. The parser splits the protected payload into ciphertext, a trailing `key56` block, and the outer hash. The key material is not taken from the first few bytes of the file.
6. The first decode stage uses the recovered `key56`, derived selectors, and the reconstructed v3 reader path to decrypt the ciphertext.
7. The second decode stage applies the MT19937-64 XOR variant currently used by the integrated path.
8. The decoded stream begins with a small prelude skip value. The extractor uses that value to find the wrapped payload offset.
9. The wrapped payload is not plain stock Zstandard. The extractor rewrites the custom YSM wrapper block headers into normal Zstandard block headers while preserving the payload bytes.
10. The resulting Zstandard stream is decompressed with the local `zstd` binary.
11. The decompressed payload is then routed to the format-specific extractor:
    - Format `31` uses the modern BOM v3 asset scanner and folder exporter.
    - Formats `1`, `9`, and `15` use the legacy section scanner and reconstruction path.
    - Compact YSGP v2 uses the compact entry parser and can dump per-entry payload/key blobs.

> [!NOTE]
> Format `31` currently has the cleanest output path because the decoded content is closer to a folder-like asset layout. The extractor can usually locate assets by property hashes and write a canonical asset folder.

> [!WARNING]
> Formats `1`, `9`, and `15` are harder because the payload contains older compiled/binary-lowered structures. The extractor has to recover sections, infer model and animation data from patterns, names, known signatures, structural rows, and conservative guesses.

## Roadmap

- Add fuller support for all known versions.
- Keep the extractor maintained for future format changes.
- Improve recovery accuracy for older binary-lowered formats.
- Continue separating user-facing extraction from internal verifier/debug tooling.

## Communication

- Discord: `nooboyeah`
- Discord server invite: https://discord.gg/h6Gy9EgcWj
- No QQ contact is provided.
- No additional contact channels are provided.

## Disclaimer of liability

This software is provided for research, interoperability, archival, and personal data recovery use. It is provided "as is", without warranty of any kind. The authors and contributors are not liable for data loss, account issues, game/mod compatibility problems, copyright misuse, service violations, damages, or any other liability arising from use of this software.

> [!IMPORTANT]
> You are responsible for making sure you have the right to extract, inspect, convert, or redistribute any model, texture, animation, or other asset you process with this tool.

## License

ILoveOpenYSM is released under the GNU Affero General Public License v3.0 or later (`AGPL-3.0-or-later`). See [LICENSE](LICENSE).

> [!NOTE]
> The AGPL license is intended to keep modified versions and network-hosted/service versions open under the same license terms.
