from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from provider1_chacha_reference import (
    SIGMA,
    _words_from_16,
    _words_from_32,
    chacha_xor_stream,
    make_state_hchacha,
)
from ysgp_outer_v3_static import (
    MAGIC_PREFIX,
    derive_selectors_from_hash,
    hash64_with_key,
    parse_outer_v3_layout,
)


INNER_HASH_KEY = 0xF346451E53A22261
OUTER_KEY_HASH_KEY = 0xA62B1A2C43842BC3
MASK32 = 0xFFFFFFFF


def _rotl32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & MASK32


def _quarter_round(st: list[int], a: int, b: int, c: int, d: int) -> None:
    st[a] = (st[a] + st[b]) & MASK32
    st[d] ^= st[a]
    st[d] = _rotl32(st[d], 16)

    st[c] = (st[c] + st[d]) & MASK32
    st[b] ^= st[c]
    st[b] = _rotl32(st[b], 12)

    st[a] = (st[a] + st[b]) & MASK32
    st[d] ^= st[a]
    st[d] = _rotl32(st[d], 8)

    st[c] = (st[c] + st[d]) & MASK32
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


def _u32le(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 4], "little")


def _u64le(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 8], "little")


def _xor_stream_variant(
    key_or_subkey32: bytes,
    secondary_qword64: int,
    rounds: int,
    src: bytes,
    layout: str,
    counter0: int,
) -> bytes:
    counter = counter0 & 0xFFFFFFFFFFFFFFFF
    out = bytearray()
    key_words = _words_from_32(key_or_subkey32)
    sec_lo = secondary_qword64 & MASK32
    sec_hi = (secondary_qword64 >> 32) & MASK32

    for off in range(0, len(src), 64):
        ctr_lo = counter & MASK32
        ctr_hi = (counter >> 32) & MASK32
        if layout == "ctr64_nonce64":
            tail = [ctr_lo, ctr_hi, sec_lo, sec_hi]
        elif layout == "nonce64_ctr64":
            tail = [sec_lo, sec_hi, ctr_lo, ctr_hi]
        elif layout == "ctr32_z_nonce64":
            tail = [ctr_lo, 0, sec_lo, sec_hi]
        elif layout == "z_ctr32_nonce64":
            tail = [0, ctr_lo, sec_lo, sec_hi]
        elif layout == "nonce64_ctr32_z":
            tail = [sec_lo, sec_hi, ctr_lo, 0]
        elif layout == "nonce64_z_ctr32":
            tail = [sec_lo, sec_hi, 0, ctr_lo]
        else:
            raise ValueError(f"unknown layout {layout}")

        initial = _words_from_16(SIGMA) + key_words + tail
        working = initial.copy()
        for _ in range(rounds // 2):
            _double_round(working)
        block = b"".join(
            ((a + b) & MASK32).to_bytes(4, "little")
            for a, b in zip(working, initial)
        )
        chunk = src[off:off + 64]
        out.extend(a ^ b for a, b in zip(chunk, block))
        counter = (counter + 1) & 0xFFFFFFFFFFFFFFFF

    return bytes(out)


def _derive_subkey_variant(
    key32: bytes,
    secondary16: bytes,
    rounds: int,
    mode: str,
) -> bytes:
    if mode == "confirmed_hchacha":
        return make_state_hchacha(key32, secondary16, 0, rounds).key_or_subkey32
    if mode == "direct_key":
        return key32

    initial = _words_from_16(SIGMA) + _words_from_32(key32) + [
        _u32le(secondary16, i) for i in range(0, 16, 4)
    ]
    working = initial.copy()
    for _ in range(rounds // 2):
        _double_round(working)

    if mode == "hchacha_feedforward":
        mixed = [(a + b) & MASK32 for a, b in zip(working, initial)]
        words = mixed[0:4] + mixed[12:16]
    elif mode == "hchacha_tail_rol8":
        words = working[0:4] + [_rotl32(w, 8) for w in working[12:16]]
    elif mode == "block_first8_raw":
        words = working[0:8]
    elif mode == "block_first8_feedforward":
        mixed = [(a + b) & MASK32 for a, b in zip(working, initial)]
        words = mixed[0:8]
    else:
        raise ValueError(f"unknown derivation mode {mode}")

    return b"".join(w.to_bytes(4, "little") for w in words)


@dataclass(frozen=True)
class CandidateProfile:
    derivation_mode: str
    state_layout: str
    counter0: int
    confidence: str


@dataclass
class ExtractorInput:
    path: Path
    chunk: bytes
    chunk_offset_in_file: int


@dataclass
class CandidateResult:
    score: int
    key_len: int
    enc_len: int
    key_hash: int
    sel_a: int
    sel_b: int
    rounds: int
    profile: CandidateProfile
    header_offset: int
    header_dword0: int
    header_dword1: int
    inner_trailer_xor: int | None
    plaintext: bytes


PROFILES: tuple[CandidateProfile, ...] = (
    CandidateProfile("confirmed_hchacha", "ctr64_nonce64", 0, "confirmed"),
    CandidateProfile("hchacha_tail_rol8", "ctr64_nonce64", 0, "tentative"),
    CandidateProfile("confirmed_hchacha", "ctr32_z_nonce64", 0, "tentative"),
    CandidateProfile("confirmed_hchacha", "nonce64_ctr64", 0, "tentative"),
    CandidateProfile("confirmed_hchacha", "z_ctr32_nonce64", 0, "tentative"),
    CandidateProfile("confirmed_hchacha", "ctr64_nonce64", 1, "tentative"),
    CandidateProfile("hchacha_feedforward", "ctr64_nonce64", 0, "tentative"),
    CandidateProfile("block_first8_raw", "ctr64_nonce64", 0, "tentative"),
    CandidateProfile("block_first8_feedforward", "ctr64_nonce64", 0, "tentative"),
    CandidateProfile("direct_key", "ctr64_nonce64", 0, "tentative"),
)


def load_input(path: Path) -> ExtractorInput:
    data = path.read_bytes()
    if data.startswith(MAGIC_PREFIX):
        layout = parse_outer_v3_layout(path)
        chunk = data[layout.separator_offset:layout.trailing_hash_offset + 8]
        return ExtractorInput(
            path=path,
            chunk=chunk,
            chunk_offset_in_file=layout.separator_offset,
        )

    if len(data) >= 13 and data[0] == 0 and _u32le(data, 1) == 3:
        return ExtractorInput(path=path, chunk=data, chunk_offset_in_file=0)

    raise ValueError("input is neither a full YSGP file nor a carved v3 chunk")


def decrypt_candidate(
    enc: bytes,
    key_blob: bytes,
    rounds: int,
    profile: CandidateProfile,
) -> bytes:
    key32 = key_blob[:32]
    secondary16 = key_blob[32:48]
    secondary_qword64 = _u64le(key_blob, 48)

    if profile.derivation_mode == "confirmed_hchacha" and profile.state_layout == "ctr64_nonce64" and profile.counter0 == 0:
        state = make_state_hchacha(
            key32=key32,
            secondary16=secondary16,
            secondary_qword64=secondary_qword64,
            rounds=rounds,
        )
        return chacha_xor_stream(state, enc)

    subkey = _derive_subkey_variant(key32, secondary16, rounds, profile.derivation_mode)
    return _xor_stream_variant(
        key_or_subkey32=subkey,
        secondary_qword64=secondary_qword64,
        rounds=rounds,
        src=enc,
        layout=profile.state_layout,
        counter0=profile.counter0,
    )


def score_plaintext(pt: bytes) -> tuple[int, int, int, int]:
    best_score = -10_000
    best_off = 0
    best_d0 = 0
    best_d1 = 0
    scan_limit = min(0x100, max(0, len(pt) - 8))
    for off in range(0, scan_limit + 1, 4):
        d0 = _u32le(pt, off)
        d1 = _u32le(pt, off + 4)
        score = 0
        if off == 0:
            score += 30
        if d0 == 1:
            score += 500
        elif d0 < 0x100:
            score += 50 - abs(d0 - 1)
        if 1 <= d1 <= 31:
            score += 200
        elif d1 < 0x100:
            score += 10
        if len(pt) > 0x100:
            score += 5
        if score > best_score:
            best_score = score
            best_off = off
            best_d0 = d0
            best_d1 = d1
    return best_score, best_off, best_d0, best_d1


def inspect_inner_trailer_xor(pt: bytes) -> int | None:
    if len(pt) < 0x108:
        return None
    observed = _u64le(pt, len(pt) - 8)
    expected = hash64_with_key(pt[:-8], INNER_HASH_KEY)
    return observed ^ expected


def evidence_bonus(
    key_len: int,
    rounds: int,
    derived_rounds: int,
    profile: CandidateProfile,
) -> int:
    bonus = 0
    if key_len == 56:
        bonus += 20
    if rounds == derived_rounds:
        bonus += 15
    if profile.confidence == "confirmed":
        bonus += 10
    return bonus


def enumerate_candidates(
    src: ExtractorInput,
    key_lens: Iterable[int],
    extra_rounds: Iterable[int],
) -> list[CandidateResult]:
    chunk = src.chunk
    if len(chunk) < 5 + 56 + 8:
        raise ValueError("chunk too short for proven v3 separator/version/body/trailer framing")
    if chunk[0] != 0 or _u32le(chunk, 1) != 3:
        raise ValueError("chunk does not begin with proven separator/version bytes")

    mid = chunk[5:-8]
    preview_rows: list[tuple[int, int, int, int, int, int, CandidateProfile, bytes, bytes]] = []
    preview_len = 0x200
    for key_len in key_lens:
        if key_len < 56 or key_len > len(mid) - 8:
            continue
        key_blob = mid[-key_len:]
        enc = mid[:-key_len]
        key_hash = hash64_with_key(key_blob, OUTER_KEY_HASH_KEY)
        sel_a, sel_b = derive_selectors_from_hash(key_hash)
        round_candidates = {sel_b}
        round_candidates.update(extra_rounds)
        round_candidates = {r for r in round_candidates if r > 0 and (r & 1) == 0}
        for rounds in sorted(round_candidates):
            for profile in PROFILES:
                preview = decrypt_candidate(enc[:preview_len], key_blob, rounds, profile)
                score, off, d0, d1 = score_plaintext(preview)
                score += evidence_bonus(key_len, rounds, sel_b, profile)
                preview_rows.append(
                    (score, key_len, len(enc), key_hash, sel_a, sel_b, profile, key_blob, rounds.to_bytes(4, "little"))
                )
    preview_rows.sort(key=lambda row: row[0], reverse=True)

    results: list[CandidateResult] = []
    for score, key_len, enc_len, key_hash, sel_a, sel_b, profile, key_blob, rounds_raw in preview_rows[:24]:
        rounds = int.from_bytes(rounds_raw, "little")
        enc = mid[:-key_len]
        pt = decrypt_candidate(enc, key_blob, rounds, profile)
        score, off, d0, d1 = score_plaintext(pt)
        score += evidence_bonus(key_len, rounds, sel_b, profile)
        trailer_xor = inspect_inner_trailer_xor(pt) if off == 0 and d0 == 1 else None
        if trailer_xor == 0:
            score += 500
        elif trailer_xor is not None and trailer_xor < (1 << 32):
            score += 25
        results.append(
            CandidateResult(
                score=score,
                key_len=key_len,
                enc_len=enc_len,
                key_hash=key_hash,
                sel_a=sel_a,
                sel_b=sel_b,
                rounds=rounds,
                profile=profile,
                header_offset=off,
                header_dword0=d0,
                header_dword1=d1,
                inner_trailer_xor=trailer_xor,
                plaintext=pt,
            )
        )
    results.sort(key=lambda r: r.score, reverse=True)
    return results


def dump_candidate(base: Path, rank: int, cand: CandidateResult) -> Path:
    name = (
        f"{base.stem}.candidate_{rank:02d}"
        f".score_{cand.score}"
        f".k{cand.key_len}"
        f".r{cand.rounds}"
        f".{cand.profile.derivation_mode}"
        f".{cand.profile.state_layout}"
        f".bin"
    )
    out_path = base.with_name(name)
    out_path.write_bytes(cand.plaintext)
    return out_path


def print_summary(src: ExtractorInput, results: list[CandidateResult], top_n: int) -> None:
    print(f"input: {src.path}")
    print(f"chunk_offset_in_file: 0x{src.chunk_offset_in_file:x}")
    print(f"chunk_len: 0x{len(src.chunk):x}")
    if not any(r.header_dword0 == 1 and 1 <= r.header_dword1 <= 31 and r.header_offset == 0 for r in results):
        print("note: no tested candidate satisfied the proven inner-header invariant at offset 0")
    for idx, cand in enumerate(results[:top_n], 1):
        print(f"[{idx}] score={cand.score} confidence={cand.profile.confidence}")
        print(
            "    key_len="
            f"0x{cand.key_len:x} enc_len=0x{cand.enc_len:x} "
            f"key_hash=0x{cand.key_hash:016x} sel_a=0x{cand.sel_a:02x} sel_b={cand.sel_b} "
            f"rounds={cand.rounds}"
        )
        print(
            "    profile="
            f"{cand.profile.derivation_mode} / {cand.profile.state_layout} / counter0={cand.profile.counter0}"
        )
        print(
            "    header="
            f"off=0x{cand.header_offset:x} dword0=0x{cand.header_dword0:08x} dword1={cand.header_dword1}"
        )
        if cand.inner_trailer_xor is not None:
            print(f"    inner_trailer_xor=0x{cand.inner_trailer_xor:016x}")
        print(f"    head64={cand.plaintext[:64].hex()}")


def build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Best-effort static end-to-end extractor for the first YSGP v3 provider path."
    )
    parser.add_argument("input", help="full .ysm/.ysgp file or carved chunk")
    parser.add_argument(
        "--key-lens",
        default="56,48,64,72,80,88,96",
        help="comma-separated candidate appended key-blob lengths to test",
    )
    parser.add_argument(
        "--extra-rounds",
        default="10,20,30",
        help="comma-separated fallback even round counts to test in addition to derived sel_b",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="number of top candidates to print",
    )
    parser.add_argument(
        "--dump-top",
        type=int,
        default=3,
        help="number of top candidate plaintexts to dump beside the input",
    )
    return parser


def main() -> int:
    args = build_argparser().parse_args()
    src = load_input(Path(args.input))
    key_lens = [int(part, 0) for part in args.key_lens.split(",") if part]
    extra_rounds = [int(part, 0) for part in args.extra_rounds.split(",") if part]
    results = enumerate_candidates(src, key_lens, extra_rounds)
    print_summary(src, results, args.top)
    for idx, cand in enumerate(results[:args.dump_top], 1):
        out_path = dump_candidate(Path(args.input), idx, cand)
        print(f"dumped[{idx}]={out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
