# ILoveOpenYSM

<p align="center">
  <a href="https://github.com/Whyaremax/ILoveOpenYSM/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/Whyaremax/ILoveOpenYSM?style=social"></a>
  <a href="https://github.com/Whyaremax/ILoveOpenYSM/network/members"><img alt="GitHub forks" src="https://img.shields.io/github/forks/Whyaremax/ILoveOpenYSM?style=social"></a>
  <a href="https://github.com/Whyaremax/ILoveOpenYSM/releases"><img alt="Release" src="https://img.shields.io/github/v/release/Whyaremax/ILoveOpenYSM?label=release"></a>
  <a href="https://github.com/Whyaremax/ILoveOpenYSM/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/github/license/Whyaremax/ILoveOpenYSM"></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.x-blue">
  <img alt="Offline tool" src="https://img.shields.io/badge/runtime-offline-brightgreen">
</p>

ILoveOpenYSM is a free, open-source, offline YSM extractor for Yes Steve Model files. It is designed for inspecting and extracting YSM, YSGP, and BOM v3 containers without relying on the original native runtime.

It also carries a small note trail for the native side, so the project is not framed as "just an extractor" with no grounding. The current public note is [`memory/native_library_runtime_evidence_may5.md`](memory/native_library_runtime_evidence_may5.md).

The workflow was inspired by the older NSM/NoSteveModel approach, but this repository is maintained as an independent project.

> [!IMPORTANT]
> ILoveOpenYSM is not affiliated with, endorsed by, maintained by, or connected to the official Yes Steve Model project, the YSM/CIT Resewn team site, or the Modrinth Yes Steve Model page.
>
> Official/project pages this repository is **not** related to:
>
> - https://ysm.cfpa.team/
> - https://modrinth.com/mod/yes-steve-model

> [!TIP]
> If this project helped you inspect or recover a model, consider starring the repository so other people can find it more easily.

## At a glance

- Offline Python extractor for YSM-related containers.
- Supports BOM v3 containers and several known codec families.
- Best current output path is format `31`.
- User-facing CLI is `ysm_extract.py`.
- Intended for research, interoperability, archival, and personal data recovery.

## Contents

- [Project status](#project-status)
- [Features](#features)
- [Boundaries and non-goals](#boundaries-and-non-goals)
- [Native runtime evidence](#native-runtime-evidence)
- [Supported formats](#supported-formats)
- [Quick start](#quick-start)
- [Common commands](#common-commands)
- [How it works](#how-it-works)
- [Accuracy expectations](#accuracy-expectations)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Communication](#communication)
- [Disclaimer of liability](#disclaimer-of-liability)
- [License](#license)

## Project status

Current release: `1.0.0`

The `1.0.0` package keeps the user-facing extractor and removes verifier/debug tooling from the public bundle. It is intended for practical offline extraction, not runtime tracing or native debugger workflows.

This repository tracks the small public offline bundle. The broader research tree contains extra reverse-engineering tools, runtime capture helpers, live parser probes, and native-truth experiments. Those tools are useful for studying YSM internals, but they are intentionally not part of this public release.

If you are using ILoveOpenYSM from this repository, the supported expectation is:

- offline extraction
- practical asset recovery
- heuristic legacy model reconstruction

It is not a promise of exact official-export parity or authored source reconstruction.

> [!WARNING]
> Do not pay for any third-party service or tool that claims to sell this project as a paid OpenYSM extractor. ILoveOpenYSM is free and open source.

## Features

- A small offline Python extractor for YSM-related containers.
- A research and interoperability tool for understanding YSM/YSGP/BOM v3 files.
- A practical exporter for supported model assets, especially format `31`.
- A public, free alternative to abandoned or closed extractor workflows.
- Asset scanning and folder export through `--scan-assets`, `--dump-assets`, and `--dump-folder`.
- Optional source-oracle restore for cases where matching original authored files are available nearby.

## Boundaries and non-goals

- It is not the official Yes Steve Model project.
- It is not connected to `ysm.cfpa.team` or the Modrinth Yes Steve Model page.
- It is not a replacement for the original mod.
- It does not provide the original native runtime capability.
- It does not guarantee official/native export parity for every legacy format.

## Native runtime evidence

This public repo does not ship the original native runtime, but the broader reverse-engineering work behind ILoveOpenYSM is grounded in direct runtime evidence instead of guesswork alone.

- `libysm-core` has been observed loading into a JVM and reaching `JNI_OnLoad`, which shows the native path is real even when later bootstrap gates still fail.
- Headed runtime tracing shows `libysm-core` directly opening and reading real `custom/*.ysm` files and `yes_steve_model/cache/server/*` cache blobs.
- The Java/Forge side owns packet transport, while native code still owns important payload and state semantics after `ByteBuffer` handoff.
- A short repo note with the current evidence and boundary is in [`memory/native_library_runtime_evidence_may5.md`](memory/native_library_runtime_evidence_may5.md).

## Supported formats

- BOM v3 YSM containers, including known format families `Legacy`, `1`, `9`, `15`, and `31`.
- Format `31` currently works best because of its simplified structure.
- Format `15` support is nearly complete.
- Legacy `<1.1.5` YSGP files are still not fully covered, although they appear to be the easiest remaining format family.
- Compact YSGP v2 can dump per-entry payload/key blobs.

> [!CAUTION]
> Legacy formats can require heuristic reconstruction. Output from formats `1`, `9`, and `15` may differ from official native export output.

## Quick start

Run commands from the repository root. Directly invoking files under `extractors/` is not the stable public interface.

```bash
python3 ysm_extract.py --help
python3 ysm_extract.py --dump-folder path/to/model.ysm
```

`ysm_extract.py` is the supported entrypoint.

`ysm_extractor.py` is included as a compatibility alias for the same CLI.

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

## Accuracy expectations

For modern assets and straightforward legacy content, the extractor is often good enough for inspection, archival, and practical reuse.

For older legacy model families, especially format-15 content with dense local pivots or layered rotations, output can still differ from:

- the original authored `main.json`
- the in-game parser-side model state
- the official Yes Steve Model export

The most common drift shows up in pivot-heavy or rotation-heavy parts such as:

- hair clusters
- tails
- masks and face accessories
- bows
- skirts or layered clothing

When matching authored detail exactly matters, the best results still come from:

- source-oracle recovery when the original authored files are available
- native/runtime research workflows kept outside this public bundle

## Roadmap

- Add fuller support for all known versions.
- Keep the extractor maintained for future format changes.
- Improve recovery accuracy for older binary-lowered formats.
- Continue separating user-facing extraction from internal verifier/debug tooling.

## Contributing

Issues and pull requests are welcome.

Useful contributions include:

- Test files from formats that are not fully supported yet.
- Bug reports with command output and container format details.
- Documentation improvements.
- Safer reconstruction logic for older binary-lowered formats.

Please do not submit proprietary native runtime files, closed-source code, or assets you do not have permission to share.

## Communication

- Discord: `nooboyeah`
- Discord server invite: https://discord.gg/h6Gy9EgcWj
- No QQ contact is provided.
- No additional contact channels are provided.

## Search keywords

YSM extractor, Yes Steve Model extractor, OpenYSM, ILoveOpenYSM, NoSteveModel alternative, NSM alternative, Minecraft YSM decoder, YSGP extractor, BOM v3 extractor, Yes Steve Model tools, Minecraft player model extractor, YSM model converter.

## Disclaimer of liability

This software is provided for research, interoperability, archival, and personal data recovery use. It is provided "as is", without warranty of any kind. The authors and contributors are not liable for data loss, account issues, game/mod compatibility problems, copyright misuse, service violations, damages, or any other liability arising from use of this software.

> [!IMPORTANT]
> You are responsible for making sure you have the right to extract, inspect, convert, or redistribute any model, texture, animation, or other asset you process with this tool.

## License

ILoveOpenYSM is released under the GNU Affero General Public License v3.0 or later (`AGPL-3.0-or-later`). See [LICENSE](LICENSE).

> [!NOTE]
> The AGPL license is intended to keep modified versions and network-hosted/service versions open under the same license terms.
