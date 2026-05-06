# Native Import And Loader Path

This note is about how the original native runtime ingests YSM data.

## Short version

- `libysm-core` directly reads both raw `custom/*.ysm` inputs and staged
  `cache/server/*` blobs.
- Those two sources converge into one loader family before deeper semantic
  parsing.
- The cache blobs are not plain `.ysm` files and are not final JSON. They are a
  later native-produced encoded stage.

## Direct headed-run evidence

In headed tracing, `libysm-core.so` itself was observed opening and reading:

- `yes_steve_model/custom/*.ysm`
- `yes_steve_model/cache/server_index`
- `yes_steve_model/cache/server/*`

The hottest repeated file-read wrappers were observed at:

- `fopen` caller rel `0x2b8500`
- `read` caller rel `0x2b85b7`

That matters because it rules out the earlier Java-side-only hypothesis for
these runtime inputs.

## What the cache proves

The persisted `cache/server/*` blobs consistently appeared in a later staged
form, for example with leading bytes like:

- `01 00 00 00 1f 00 00 00 ...`

That is different from:

- compact YSGP v2 files beginning with `YSGP`
- BOM v3 files beginning with UTF-8 BOM + `YSGP`

So the cache is an inner native stage, not just the original file copied
forward.

## Loader convergence

Static correlation tied the live reads back to the loader family around:

- `FUN_004d5fe0`
- `FUN_005d5f80`
- `FUN_005d6180`

The best current model is:

1. a chosen source path is promoted into one selected ingest path
2. `FUN_005d5f80` builds staged reader state for that file
3. `FUN_005d6180` materializes per-entry staged bytes
4. later semantic builders consume those staged bytes

This is the important convergence point where:

- raw `custom/*.ysm`
- reused `cache/server/*`

are normalized into the same downstream loader family.

## Runtime directory picture

The broader runtime path map also shows named roots such as:

- `yes_steve_model/custom`
- `yes_steve_model/auth`
- `yes_steve_model/builtin`
- `yes_steve_model/export`
- `yes_steve_model/cache/server_index`
- `yes_steve_model/cache/server`
- `yes_steve_model/cache/client`

That picture is useful because it explains why the public extractor and the
native runtime are related but not identical. The native side is operating over
runtime directories and staged caches, not only over standalone files.

## Additional confidence signal

Headed-run logs also showed that hotloaded content made it farther than raw file
ingestion and cache creation. It reached later semantic/runtime work such as
Molang parsing, which helps confirm that the path is not stopping at shallow
file I/O.
