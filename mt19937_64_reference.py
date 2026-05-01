from __future__ import annotations

from dataclasses import dataclass, field


NN = 312
MM = 156
MATRIX_A = 0xB5026F5AA96619E9
UM = 0xFFFFFFFF80000000
LM = 0x7FFFFFFF
INIT_F = 0x5851F42D4C957F2D
MASK64 = 0xFFFFFFFFFFFFFFFF
TEMPER_MASK_A = 0x5555555555555555
TEMPER_MASK_B = 0x71D67FFFEDA60000
TEMPER_MASK_C = 0xFFF7EEE000000000


@dataclass
class MT19937_64:
    """
    Reference for the second-stage seeded PRNG used on the v3 path.

    Confirmed from static evidence:
    - state size is 312 qwords
    - seed recurrence uses 0x5851f42d4c957f2d
    - generator state index is initialized to 0x138
    - output is consumed as qwords and XORed against the byte stream

    Confirmed from the recovered constants in the native library:
    - the core matches stock MT19937-64 twist/temper
    """

    state: list[int] = field(default_factory=lambda: [0] * NN)
    index: int = NN

    @classmethod
    def from_seed(cls, seed: int) -> "MT19937_64":
        seed &= MASK64
        mt = cls()
        mt.state[0] = seed
        for i in range(1, NN):
            prev = mt.state[i - 1]
            mt.state[i] = (INIT_F * (prev ^ (prev >> 62)) + i) & MASK64
        mt.index = NN
        return mt

    def _twist(self) -> None:
        for i in range(NN):
            x = (self.state[i] & UM) | (self.state[(i + 1) % NN] & LM)
            xa = x >> 1
            if x & 1:
                xa ^= MATRIX_A
            self.state[i] = self.state[(i + MM) % NN] ^ xa
        self.index = 0

    def next_u64(self) -> int:
        if self.index >= NN:
            self._twist()

        x = self.state[self.index]
        self.index += 1

        x ^= (x >> 29) & TEMPER_MASK_A
        x ^= (x << 17) & TEMPER_MASK_B
        x ^= (x << 37) & TEMPER_MASK_C
        x ^= x >> 43
        return x & MASK64

    def xor_stream(self, src: bytes) -> bytes:
        out = bytearray(len(src))
        off = 0
        while off + 8 <= len(src):
            ks = self.next_u64().to_bytes(8, "little")
            for i in range(8):
                out[off + i] = src[off + i] ^ ks[i]
            off += 8
        if off < len(src):
            ks = self.next_u64().to_bytes(8, "little")
            for i in range(len(src) - off):
                out[off + i] = src[off + i] ^ ks[i]
        return bytes(out)

    def xor_stream_endian(self, src: bytes, byteorder: str) -> bytes:
        if byteorder not in {"little", "big"}:
            raise ValueError(f"unsupported byteorder {byteorder}")
        out = bytearray(len(src))
        off = 0
        while off + 8 <= len(src):
            ks = self.next_u64().to_bytes(8, byteorder)
            for i in range(8):
                out[off + i] = src[off + i] ^ ks[i]
            off += 8
        if off < len(src):
            ks = self.next_u64().to_bytes(8, byteorder)
            for i in range(len(src) - off):
                out[off + i] = src[off + i] ^ ks[i]
        return bytes(out)

    def xor_stream_phase(self, src: bytes, phase: int, byteorder: str = "little") -> bytes:
        if byteorder not in {"little", "big"}:
            raise ValueError(f"unsupported byteorder {byteorder}")
        if phase < 0 or phase > 7:
            raise ValueError(f"unsupported phase {phase}")
        if not src:
            return b""

        out = bytearray(len(src))
        ks = bytearray()
        while len(ks) < len(src) + phase:
            ks.extend(self.next_u64().to_bytes(8, byteorder))
        ks = memoryview(ks)[phase:phase + len(src)]
        for i, b in enumerate(src):
            out[i] = b ^ ks[i]
        return bytes(out)
