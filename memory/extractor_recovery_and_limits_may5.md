# Extractor Recovery And Limits

This note summarizes what the public extractor can recover today and where the
important gaps still are.

## BOM v3 path

The BOM + `YSGP` v3 lane is the strongest offline recovery story.

The current confirmed path is:

1. parse the BOM + `YSGP` container framing
2. recover the protected payload split
3. rebuild the custom wrapped stream into stock Zstandard blocks
4. decompress to the inner payload stream
5. mine named asset sections from the decoded payload

Practical confirmed outcomes include:

- exact inline PNG extraction with hash verification
- compiled model/animation section carving
- manifest generation around recovered sections

The property block provides a strong validation oracle because the embedded
64-hex asset identifiers match SHA-256 hashes of original export assets such as:

- `main.json`
- `arm.json`
- `arrow.json`

## Compact YSGP v2 path

The compact v2 outer framing is structurally recovered well enough to index
entries and dump per-entry payload/key blobs.

Important recovered facts include:

- `YSGP` magic
- big-endian version field
- file-level MD5 over the post-header region
- base64-encoded names such as `main.json`, `arm.json`, and textures

That means the outer structure is understood even where deeper provider-side
content decoding still needs more work.

## Legacy low-format path

For older legacy families, the current picture is more mixed.

The best current model is:

- formats `1`, `9`, and `15` share one lower native builder family
- `format 15` extends the same core with extra resource/sound behavior
- the public Python path often has to reconstruct semantics heuristically

This is why legacy output can still differ from:

- official export
- paired source trees
- in-game parser/runtime state

## Why the limits are real

The current limits are not only guesswork or lack of polishing.
They come from direct comparison against:

- official export snapshots
- paired source trees
- native/runtime evidence

That comparison is why the repo is explicit about:

- heuristic reconstruction
- source-oracle restore when original authored files exist nearby
- remaining drift for pivot-heavy and rotation-heavy legacy models

## Practical takeaway

ILoveOpenYSM is already useful for:

- inspection
- archival
- asset recovery
- practical decoding of modern and some legacy containers

But it should still be read as:

- strong offline extraction for many cases
- conservative legacy reconstruction for the harder old formats

not as a blanket claim of native-identical export parity.
