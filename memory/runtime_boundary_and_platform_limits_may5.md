# Runtime Boundary And Platform Limits

This note summarizes two easy-to-confuse boundaries:

- what Java/Forge handles versus what the native library handles
- what the stock runtime can and cannot do on non-supported platforms

## Java transport vs native semantics

The packet transport layer is normal Java/Forge networking.

The key class creates a standard `SimpleChannel` and registers packet handlers
for both directions. That means:

- connection transport
- packet framing
- channel-version handshake
- packet dispatch

are normal Java/Forge responsibilities.

But the important payload/state path still crosses into native code after packet
bytes are handed off through direct `ByteBuffer` flows.

So the correct model is:

- Java owns transport
- native owns important payload/model/state semantics

That is why removing the native library is not a small patch.

## Server-side dependence

The native layer is not only a client-renderer detail.

The broader runtime boundary work showed native entrypoints involved in:

- payload handlers
- model lookup / validation-style flows
- rebuild / reload style flows
- sync state for player/model sets

So both client and server behavior depend on the native contract.

## Platform limit

For stock YSM `2.6.2`, the bundled native artifacts include:

- `libysm-core.so`
- `libysm-core-android.so`
- `ysm-core.dll`

There is no macOS `.dylib`.

The loader also explicitly branches for supported platforms and rejects others
before the runtime is considered available.

## Practical conclusion

An unmodified stock runtime is not meaningfully cross-platform just because the
Java-side transport exists.

Without either:

- a real native port
- or a compatible Java reimplementation of the native contract

the runtime cannot simply be "patched around" by removing one load check.

This platform boundary is relevant to ILoveOpenYSM because it helps explain why
an offline extractor matters in the first place: the public extractor is useful
even when the full native runtime is unavailable or impractical.
