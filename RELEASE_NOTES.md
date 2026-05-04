# ILoveOpenYSM 1.0.0

Initial standalone release.

## Included

- `ysm_extract.py` supported CLI entrypoint.
- `ysm_extractor.py` compatibility alias.
- BOM v3 decode and asset export helpers.
- Compact YSGP v2 parser.
- Source-oracle restore helpers.
- Current public license and README with liability disclaimer.

This release is focused on offline extraction.

## Repository refresh

Post-release repository updates may refresh documentation and clarify scope without widening the package boundary.

Current supported boundary:

- offline extractor bundle only
- no live runtime capture helpers
- no Windows automation
- no native-truth debugger tooling

Current practical expectation:

- useful offline extraction and asset recovery
- heuristic reconstruction for legacy models
- no guarantee of exact official-export parity on pivot-heavy legacy content
