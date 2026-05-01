from __future__ import annotations


MASK64 = 0xFFFFFFFFFFFFFFFF

# Confirmed from the BOM + YSGP v3 branch in FUN_00556b60.
MIX_C1 = 0xAF29CE778879D9C7  # -0x50d6318877862639
MIX_C2 = 0xAF29CE778879DA37  # -0x50d63188778625c9
MIX_C3 = 0x50D6318877862639
MIX_C4 = 0xDE0F6EE09BDBAB91  # -0x21f0911f6424546f

SELECTOR_SEED_KEY = 0xA62B1A2C43842BC3
SECOND_STAGE_SEED_KEY = 0xD017CBBA7B5D3581


def _u64le(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 8], "little")


def _rol64(value: int, count: int) -> int:
    value &= MASK64
    return ((value << count) | (value >> (64 - count))) & MASK64


def _bswap64(value: int) -> int:
    return int.from_bytes(value.to_bytes(8, "little"), "big")


def mix56_exact(seed56: bytes, seed_key: int) -> int:
    """
    Exact fixed-size 56-byte mixer recovered from the BOM v3 path in FUN_00556b60.

    Confirmed:
    - input is exactly seven little-endian qwords
    - the selector hash and the second-stage PRNG seed both use this mixer
    - this differs from the generic hash64_with_key() helper used elsewhere
    """

    if len(seed56) != 56:
        raise ValueError(f"expected 56 seed bytes, got {len(seed56)}")

    q0 = _u64le(seed56, 0x00)
    q1 = _u64le(seed56, 0x08)
    q2 = _u64le(seed56, 0x10)
    q3 = _u64le(seed56, 0x18)
    q4 = _u64le(seed56, 0x20)
    q5 = _u64le(seed56, 0x28)
    q6 = _u64le(seed56, 0x30)

    l20 = (q3 * 9) & MASK64
    u19 = ((q0 * MIX_C1) + q6) & MASK64
    u9 = ((q2 * MIX_C1) + l20) & MASK64
    l17 = (_rol64(u9, 22) + q4) & MASK64
    u21 = (
        (
            (((_rol64(q1, 34) + q4) & MASK64) * 9)
            + _rol64(u19, 21)
            + (u19 ^ q3)
            + l20
            + 1
        )
        * MIX_C2
    ) & MASK64
    l12 = (q5 * MIX_C2) & MASK64
    u19 = ((l12 + l20 + (u19 ^ q3) + 1 + _bswap64(u21)) * MIX_C2) & MASK64
    u19 = ((q6 + u9 + q4 + l17 + _bswap64(u19)) * MIX_C2) & MASK64
    u16 = (l12 + q3 + ((u9 + q4 + q1 + _bswap64(u19)) * MIX_C2)) & MASK64
    u18 = (l17 + MIX_C3 + (((u16 >> 47) ^ u16) * MIX_C2)) & MASK64
    out = ((u18 ^ seed_key) * MIX_C4) & MASK64
    out = ((((out >> 47) ^ u18 ^ out) * MIX_C4)) & MASK64
    out = ((((out >> 47) ^ out) * MIX_C4)) & MASK64
    return out


def derive_selectors_exact(seed56: bytes) -> tuple[int, int, int]:
    h = mix56_exact(seed56, SELECTOR_SEED_KEY)
    sel_a = (h & 0x3F) | 0x40
    sel_b = 10 + 10 * (h % 3)
    return h, sel_a, sel_b

