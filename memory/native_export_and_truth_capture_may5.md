# Native Export And Truth Capture

This note summarizes what is currently known about the official export path and
how it was compared against the public extractor.

## Short version

- The headed runtime uses `config/yes_steve_model/export` as its export root.
- The command shape recovered from the official jar is `/ysm export <model_id> [extra]`.
- Official export output can be harvested, normalized, and compared against both
  paired source trees and the Python extractor output.

## Output root and command shape

The current confirmed native/export-side truths are:

- input root used in headed truth-capture work:
  - `config/yes_steve_model/custom/*.ysm`
- output root used by the official runtime:
  - `config/yes_steve_model/export`
- command root:
  - `ysm`
- export subcommand:
  - `export`

That is the basis of the local truth-capture tooling, even though that tooling
is not shipped in this public repo.

## Export naming evidence

The native side clearly knows about export names such as:

- `main.json`
- `arm.json`
- `arrow.json`
- `legacy-`

For the low-format native builder, the strongest current mapping is:

- type `3` is the arrow-special family
- the two generic primary families correspond to `main` and `arm`

That matches both:

- export-side naming strings
- recovered legacy asset manifests

## Truth-capture workflow

The broader research tree added a capture path that:

1. stages a sample into the runtime custom folder
2. points at the real `/ysm export ...` command shape
3. harvests raw export output from `config/yes_steve_model/export`
4. snapshots it into a canonical flat `official_export_snapshot/`
5. compares:
   - Python output vs official export
   - official export vs paired source

This is important because it keeps the verifier lane anchored to real runtime
truth instead of only to hand-maintained source trees.

## What the comparisons showed

For paired Wine Fox legacy samples, the captured official-export snapshot
matched the paired source side on the official-vs-source axis, while the Python
extractor still showed known geometry/resource mismatches in harder legacy
families.

That is the cleanest statement of the current boundary:

- official export is the ground-truth output we compare against
- the public Python extractor is useful, but it is not yet identical to the
  native export path for every legacy case

## What this means for ILoveOpenYSM

ILoveOpenYSM does not bundle the official export runtime, but the project is
still guided by that export truth.

That is why the repo talks about:

- heuristic reconstruction
- source-oracle restore where available
- limits for older binary-lowered formats

Those are not random disclaimers. They come from direct comparison against the
native export surface.
