# Native Library Runtime Evidence

This repo is mainly the public offline extractor/decoder bundle, but the
extractor direction is informed by direct evidence about what the original
native library actually does.

## Short version

- `libysm-core` is a real working native runtime, not a placeholder.
- We have seen it load into a JVM, reach `JNI_OnLoad`, and continue far enough
  to hit later Forge/bootstrap checks.
- We have also traced the library itself opening and reading real
  `custom/*.ysm` files and `yes_steve_model/cache/server/*` cache blobs during
  a headed run.
- The Java/Forge layer owns packet transport, but native code still owns
  important payload/state semantics after `ByteBuffer` handoff.

## Why we believe this

### 1. Load proof

A minimal JVM probe reached the native load path and `JNI_OnLoad`. After the
right launcher/JVM-origin spoofing and Forge jars were present, the failure
shifted deeper into Forge/bootstrap state instead of dying at the first native
load step. That means the library is not just present on disk; it is actually
executing native startup logic.

### 2. File-ingestion proof

In a headed runtime trace, `libysm-core` itself was observed opening and
reading:

- `yes_steve_model/custom/*.ysm`
- `yes_steve_model/cache/server_index`
- hashed blobs under `yes_steve_model/cache/server/*`

That is strong evidence that the native library directly ingests both user
model files and the persisted cache layer.

### 3. Network boundary proof

The normal packet transport is still Java/Forge `SimpleChannel` networking.
But once packet bytes are handed off through direct `ByteBuffer` paths, key YSM
payload/state behavior still crosses into native handlers. So the native layer
is not the socket transport, but it is part of the real runtime semantics.

## What this means for ILoveOpenYSM

- ILoveOpenYSM remains the public offline extractor/decoder path.
- It does not bundle or require the original native library.
- The native evidence matters because it tells us the official runtime is doing
  real decode/state work, which helps explain why older formats need careful
  reconstruction instead of shallow file dumping.

## Current limit

Stock YSM `2.6.2` still has no macOS `.dylib`, and the unmodified runtime
still depends on native init plus later Forge/bootstrap state. So this note is
evidence about how the native library works, not a claim that the public repo
ships the native runtime.
