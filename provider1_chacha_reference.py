from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


SIGMA = b"expand 32-byte k"


def _rotl32(v: int, n: int) -> int:
    v &= 0xFFFFFFFF
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _u32le_from(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 4], "little")


def _u64le_from(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 8], "little")


def _words_from_16(data16: bytes) -> list[int]:
    if len(data16) != 16:
        raise ValueError(f"expected 16 bytes, got {len(data16)}")
    return [_u32le_from(data16, i) for i in range(0, 16, 4)]


def _words_from_32(data32: bytes) -> list[int]:
    if len(data32) != 32:
        raise ValueError(f"expected 32 bytes, got {len(data32)}")
    return [_u32le_from(data32, i) for i in range(0, 32, 4)]


def _quarter_round(st: list[int], a: int, b: int, c: int, d: int) -> None:
    st[a] = (st[a] + st[b]) & 0xFFFFFFFF
    st[d] ^= st[a]
    st[d] = _rotl32(st[d], 16)

    st[c] = (st[c] + st[d]) & 0xFFFFFFFF
    st[b] ^= st[c]
    st[b] = _rotl32(st[b], 12)

    st[a] = (st[a] + st[b]) & 0xFFFFFFFF
    st[d] ^= st[a]
    st[d] = _rotl32(st[d], 8)

    st[c] = (st[c] + st[d]) & 0xFFFFFFFF
    st[b] ^= st[c]
    st[b] = _rotl32(st[b], 7)


def _double_round(st: list[int]) -> None:
    _quarter_round(st, 0, 4, 8, 12)
    _quarter_round(st, 1, 5, 9, 13)
    _quarter_round(st, 2, 6, 10, 14)
    _quarter_round(st, 3, 7, 11, 15)
    _quarter_round(st, 0, 5, 10, 15)
    _quarter_round(st, 1, 6, 11, 12)
    _quarter_round(st, 2, 7, 8, 13)
    _quarter_round(st, 3, 4, 9, 14)


def _validate_even_rounds(rounds: int) -> None:
    if rounds <= 0 or (rounds & 1) != 0:
        raise ValueError(
            f"provider path requires a positive even round count, got {rounds}"
        )


def hchacha20_like_32(key32: bytes, input16: bytes, rounds: int) -> bytes:
    """
    Reference for first-provider slot +0x28 / FUN_002d85e2.

    Proven properties:
    - 32-byte key input
    - 16-byte secondary input
    - 32-byte output
    - ChaCha quarter-round structure
    - even round loop count supplied directly by caller
    - output words are final state 0..3 and 12..15 with no feed-forward addition

    Conservative note:
    - caller-level selector-to-round policy remains unresolved even though the
      provider body itself is now exact for the first provider.
    """
    _validate_even_rounds(rounds)
    st = _words_from_16(SIGMA) + _words_from_32(key32) + _words_from_16(input16)
    for _ in range(rounds // 2):
        _double_round(st)
    out_words = st[0:4] + st[12:16]
    return b"".join(w.to_bytes(4, "little") for w in out_words)


@dataclass
class Provider1State:
    """
    Exact state layout consumed by FUN_002d75c0.

    Offsets proven from the wrappers and core:
    - +0x00..+0x1f : 32-byte key or derived subkey
    - +0x20..+0x27 : 64-bit counter
    - +0x28..+0x2f : 64-bit secondary qword / nonce tail
    - +0x30..+0x37 : round count
    - +0x38..+0x3f : not read by the recovered core
    """

    key_or_subkey32: bytes
    counter64: int
    secondary_qword64: int
    rounds: int

    def __post_init__(self) -> None:
        if len(self.key_or_subkey32) != 32:
            raise ValueError("key_or_subkey32 must be 32 bytes")
        _validate_even_rounds(self.rounds)
        self.counter64 &= 0xFFFFFFFFFFFFFFFF
        self.secondary_qword64 &= 0xFFFFFFFFFFFFFFFF

    def as_words(self) -> list[int]:
        key_words = _words_from_32(self.key_or_subkey32)
        ctr_lo = self.counter64 & 0xFFFFFFFF
        ctr_hi = (self.counter64 >> 32) & 0xFFFFFFFF
        sec_lo = self.secondary_qword64 & 0xFFFFFFFF
        sec_hi = (self.secondary_qword64 >> 32) & 0xFFFFFFFF
        return _words_from_16(SIGMA) + key_words + [ctr_lo, ctr_hi, sec_lo, sec_hi]


def chacha_block_from_state(state: Provider1State) -> bytes:
    """
    Reference for one 64-byte block from provider slot +0x20 / FUN_002d75c0.
    """
    working = state.as_words()
    initial = working.copy()
    for _ in range(state.rounds // 2):
        _double_round(working)
    out = []
    for a, b in zip(working, initial):
        out.append(((a + b) & 0xFFFFFFFF).to_bytes(4, "little"))
    state.counter64 = (state.counter64 + 1) & 0xFFFFFFFFFFFFFFFF
    return b"".join(out)


def chacha_xor_stream(state: Provider1State, src: bytes) -> bytes:
    out = bytearray()
    off = 0
    while off < len(src):
        block = chacha_block_from_state(state)
        take = min(64, len(src) - off)
        chunk = src[off:off + take]
        out.extend(a ^ b for a, b in zip(chunk, block[:take]))
        off += take
    return bytes(out)


def make_state_direct(key32: bytes, secondary_qword64: int, rounds: int) -> Provider1State:
    """
    Reference for FUN_002d86c1-style packing.
    """
    return Provider1State(
        key_or_subkey32=key32,
        counter64=0,
        secondary_qword64=secondary_qword64,
        rounds=rounds,
    )


def make_state_hchacha(
    key32: bytes,
    secondary16: bytes,
    secondary_qword64: int,
    rounds: int,
) -> Provider1State:
    """
    Reference for the observed FUN_005d7710-style packing:
    - secondary16 goes into slot +0x28 derivation
    - the extra qword later becomes state +0x28
    - rounds become state +0x30
    """
    subkey32 = hchacha20_like_32(key32, secondary16, rounds)
    return Provider1State(
        key_or_subkey32=subkey32,
        counter64=0,
        secondary_qword64=secondary_qword64,
        rounds=rounds,
    )


@dataclass
class BufferSpan:
    data: bytes = b""
    pos: int = 0

    @property
    def remaining(self) -> bytes:
        return self.data[self.pos:]

    def consume(self, n: int) -> bytes:
        chunk = self.data[self.pos:self.pos + n]
        self.pos += len(chunk)
        return chunk


@dataclass
class Provider1Object:
    """
    Reference wrapper for the recovered object behavior.

    This models:
    - FUN_005d7710-style initializer
    - FUN_005d8890 streaming append
    - FUN_005d80c0 full-block processing
    - FUN_005d8340 tail flush / finalize
    """

    state: Provider1State
    carry_capacity: int
    downstream: bytearray = field(default_factory=bytearray)
    carry: bytearray = field(default_factory=bytearray)
    pending_block: bytearray = field(default_factory=bytearray)

    def __post_init__(self) -> None:
        if self.carry_capacity <= 0 or (self.carry_capacity & 0x3F) != 0:
            raise ValueError("carry_capacity must be a positive multiple of 64")

    def _emit_full_blocks(self, src: bytes) -> int:
        full = len(src) & ~0x3F
        if full:
            self.downstream.extend(chacha_xor_stream(self.state, src[:full]))
        tail = src[full:]
        if tail:
            self.pending_block.extend(tail)
        return full

    def _consume_pending_then_blocks(self, src: bytes, finalize: bool) -> int:
        local = bytearray(src)

        if self.pending_block and len(self.pending_block) + len(local) >= 64:
            need = 64 - len(self.pending_block)
            self.pending_block.extend(local[:need])
            del local[:need]
            self.downstream.extend(chacha_xor_stream(self.state, bytes(self.pending_block)))
            self.pending_block.clear()

        emitted = self._emit_full_blocks(bytes(local))

        if finalize and self.pending_block:
            self.downstream.extend(chacha_xor_stream(self.state, bytes(self.pending_block)))
            self.pending_block.clear()

        return emitted

    def update(self, data: bytes) -> int:
        """
        Reference for FUN_005d8890:
        buffer until carry_capacity, then route through full-block path.
        Returns emitted length rounded down to 64-byte blocks.
        """
        emitted = 0
        view = memoryview(data)
        while view:
            take = min(len(view), self.carry_capacity - len(self.carry))
            self.carry.extend(view[:take])
            view = view[take:]
            if len(self.carry) == self.carry_capacity:
                emitted += self.process_full_blocks(bytes(self.carry))
                self.carry.clear()
        return emitted

    def process_full_blocks(self, src: bytes) -> int:
        """
        Reference for FUN_005d80c0.
        Emits only full 64-byte blocks and leaves any short tail buffered.
        """
        before = len(self.downstream)
        self._consume_pending_then_blocks(src, finalize=False)
        return len(self.downstream) - before

    def flush(self) -> int:
        """
        Reference for FUN_005d8a40 -> FUN_005d8340.
        Flushes the carry buffer through the tail-finalize path.
        """
        if not self.carry:
            return 0
        data = bytes(self.carry)
        self.carry.clear()
        return self.finalize_tail(data)

    def finalize_tail(self, src: bytes) -> int:
        """
        Reference for FUN_005d8340.
        Processes pending block completion, full blocks, and the final short tail.
        """
        before = len(self.downstream)
        self._consume_pending_then_blocks(src, finalize=True)
        return len(self.downstream) - before


def demo_provider1_file(path: Path, key32: bytes, nonce24: bytes, rounds: int, carry_blocks: int) -> bytes:
    data = path.read_bytes()
    state = make_state_hchacha(
        key32=key32,
        secondary16=nonce24[:16],
        secondary_qword64=_u64le_from(nonce24, 16),
        rounds=rounds,
    )
    obj = Provider1Object(state=state, carry_capacity=carry_blocks << 6)
    obj.update(data)
    obj.flush()
    return bytes(obj.downstream)
