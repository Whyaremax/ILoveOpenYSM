from __future__ import annotations

import argparse
import base64
import os
import shlex
import sys
from pathlib import Path
from typing import Iterable

from extractors.bom_v3_end_to_end_parser import decode_bom_v3, export_or_restore_bom_v3_assets
from extractors.ysgp_compact_v2_parser import extract_entry_payloads, parse_compact_v2_file
from ysgp_outer_v3_static import MAGIC_PREFIX


def _sanitize_name(name: str) -> str:
    out: list[str] = []
    for ch in name:
        if ch.isalnum() or ch in ("-", "_", "."):
            out.append(ch)
        else:
            out.append("_")
    return "".join(out) or "entry"


def _format_family(codec_format: int | None) -> str:
    if codec_format == 31:
        return "modern_31"
    if codec_format in (1, 9, 15):
        return "legacy_1_9_15"
    if codec_format is None:
        return "unknown"
    return f"unsupported_{codec_format}"


def _detect_container(data: bytes) -> tuple[str, int | None]:
    if data.startswith(MAGIC_PREFIX):
        return ("bom_v3", 3)
    if data[:4] == b"YSGP" and len(data) >= 8:
        ver_be = int.from_bytes(data[4:8], "big")
        return ("compact_ysgp", ver_be)
    return ("unknown", None)


def _handle_bom_v3(path: Path, args: argparse.Namespace) -> None:
    result = decode_bom_v3(path)

    print(f"file: {path}")
    print("container: bom_v3")
    print(f"codec_format: {result.codec_format}")
    print(f"format_family: {_format_family(result.codec_format)}")
    print(f"prelude_skip: {result.prelude_skip}")
    print(f"wrapped_offset: 0x{result.wrapped_offset:x}")
    print(f"transcoded_zst_len: 0x{len(result.transcoded_zst):x}")
    print(f"decoded_len: 0x{len(result.decompressed):x}")
    print(f"decoded_head64: {result.decompressed[:64].hex()}")

    if args.dump_zst:
        zst_path = path.with_name(f"{path.stem}.transcoded.zst")
        zst_path.write_bytes(result.transcoded_zst)
        print(f"dump_zst: {zst_path}")

    if args.dump_decoded:
        decoded_path = path.with_name(f"{path.stem}.decoded.bin")
        decoded_path.write_bytes(result.decompressed)
        print(f"dump_decoded: {decoded_path}")

    if args.scan_assets or args.dump_assets or args.dump_folder or args.source_oracle is not None:
        exported_dir, source_oracle_path, oracle = export_or_restore_bom_v3_assets(
            path,
            result.codec_format,
            scan_assets=args.scan_assets,
            dump_assets=args.dump_assets,
            dump_folder=args.dump_folder,
            debug=args.debug,
            source_oracle=args.source_oracle,
            legacy_auto_source_oracle=args.auto_source_oracle,
        )
        if exported_dir is not None:
            print(f"dump_folder: {exported_dir}")
        if oracle is not None and source_oracle_path is not None:
            if args.source_oracle is not None:
                print(f"source_oracle_restore: {oracle.out_dir}")
            else:
                print(f"source_oracle_auto: {source_oracle_path} ({oracle.match_count}/{oracle.asset_count})")
                print(f"source_oracle_restore: {oracle.out_dir}")
            print(f"source_oracle_match: {oracle.match_count}/{oracle.asset_count}")
            print(f"exact_restore_complete: {str(oracle.exact_complete).lower()}")


def _dump_compact_entries(path: Path, dump_entries: bool) -> None:
    container = parse_compact_v2_file(path)
    print(f"file: {path}")
    print("container: compact_v2")
    print(f"version_be: {container.version_be}")
    print(f"header_md5_16: {container.header_md5_16.hex()}")
    print(f"header_md5_verified: {container.header_md5_verified}")
    print(f"entry_count: {len(container.entries)}")

    for entry, payload, key in extract_entry_payloads(container):
        if entry.name_decoded is not None:
            name = entry.name_decoded
        else:
            try:
                name = base64.b64decode(entry.name_b64, validate=False).decode("utf-8", "replace")
            except Exception:
                name = entry.name_b64.decode("ascii", "replace")
        print(
            f"entry[{entry.index}]: off=0x{entry.entry_offset:x} id={entry.entry_id.hex()} "
            f"name={name!r} payload_len=0x{entry.payload_len:x} key_len=0x{entry.key_len:x}"
        )

        if dump_entries:
            base_name = _sanitize_name(name)
            payload_path = path.with_name(f"{path.stem}.entry_{entry.index:02d}.{base_name}.payload.bin")
            key_path = path.with_name(f"{path.stem}.entry_{entry.index:02d}.{base_name}.key.bin")
            payload_path.write_bytes(payload)
            key_path.write_bytes(key)
            print(f"entry[{entry.index}].payload_dump: {payload_path}")
            print(f"entry[{entry.index}].key_dump: {key_path}")


def _handle_compact(path: Path, version_be: int, args: argparse.Namespace) -> None:
    if version_be == 2:
        _dump_compact_entries(path, dump_entries=args.dump_entries)
        return
    if version_be == 1:
        print(f"file: {path}")
        print("container: compact_v1")
        print("status: detected but not yet integrated in this release")
        return
    print(f"file: {path}")
    print(f"container: compact_ysgp(version={version_be})")
    print("status: unsupported")


def _iter_inputs(paths: Iterable[str]) -> Iterable[Path]:
    for p in paths:
        yield Path(p)


def _interactive_banner() -> str:
    return "\n".join(
        (
            "ILoveOpenYSM",
            "------------",
            "Mode: offline heuristic extractor output, not official/native export parity.",
            "Toggle options, then run extraction.",
            "Commands: number=toggle  s=source oracle path  r=run  q=quit",
        )
    )


def _interactive_option_rows(args: argparse.Namespace) -> list[tuple[str, str, str]]:
    return [
        ("1", "dump_folder", "Export canonical asset folder"),
        ("2", "scan_assets", "Scan decoded payload for assets"),
        ("3", "dump_assets", "Dump discovered assets"),
        ("4", "dump_decoded", "Dump fully decoded payload"),
        ("5", "dump_zst", "Dump transcoded zstd stream"),
        ("6", "debug", "Keep decoder-side artifacts"),
        ("7", "dump_entries", "Compact v2: dump per-entry payload/key blobs"),
        ("8", "auto_source_oracle", "Auto source-oracle restore for legacy 1/9/15"),
    ]


def _print_interactive_menu(args: argparse.Namespace) -> None:
    print(_interactive_banner())
    for key, attr, label in _interactive_option_rows(args):
        mark = "x" if bool(getattr(args, attr)) else " "
        print(f" {key}. [{mark}] {label}")
    src = str(args.source_oracle) if args.source_oracle is not None else "(auto/off)"
    print(f" s.     Source oracle path: {src}")


def _prompt_paths() -> list[str]:
    while True:
        raw = input("YSM path(s): ").strip()
        if not raw:
            print("Enter at least one file path.")
            continue
        parts = shlex.split(raw)
        if not parts:
            print("Enter at least one file path.")
            continue
        return parts


def _interactive_args(base_args: argparse.Namespace) -> argparse.Namespace:
    args = argparse.Namespace(**vars(base_args))
    if not args.dump_folder and not args.scan_assets and not args.dump_assets and not args.dump_entries:
        args.dump_folder = True
    while True:
        print()
        _print_interactive_menu(args)
        choice = input("Select option: ").strip().lower()
        if choice in {"q", "quit", "exit"}:
            raise SystemExit(0)
        if choice in {"r", "run", ""}:
            args.inputs = _prompt_paths()
            return args
        if choice == "s":
            raw = input("Source oracle path (empty to clear): ").strip()
            args.source_oracle = Path(raw).expanduser() if raw else None
            continue
        toggles = {key: attr for key, attr, _label in _interactive_option_rows(args)}
        attr = toggles.get(choice)
        if attr is None:
            print("Unknown selection.")
            continue
        setattr(args, attr, not bool(getattr(args, attr)))


def build_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="ILoveOpenYSM 1.0.0 offline extractor for YSM/BOM v3 and compact YSGP v2 files.",
        epilog=(
            "Bare input extraction and interactive mode use a heuristic Python extractor. "
            "Legacy output can differ from official YSM export output."
        ),
    )
    ap.add_argument("inputs", nargs="*", help="Input YSM/YSGP files")
    ap.add_argument("--interactive", action="store_true", help="launch interactive menu mode")

    ap.add_argument("--dump-zst", action="store_true", help="BOM v3: dump transcoded zstd stream")
    ap.add_argument("--dump-decoded", action="store_true", help="BOM v3: dump fully decoded payload")
    ap.add_argument("--scan-assets", action="store_true", help="BOM v3: scan decoded payload for assets")
    ap.add_argument("--dump-assets", action="store_true", help="BOM v3: dump discovered assets")
    ap.add_argument("--dump-folder", action="store_true", help="BOM v3: export canonical asset folder")
    ap.add_argument("--debug", action="store_true", help="keep decoder-side artifacts like section bins and manifests")

    ap.add_argument(
        "--source-oracle",
        type=Path,
        help="BOM v3: restore exact files from this source folder or zip archive",
    )
    ap.add_argument(
        "--no-auto-source-oracle",
        action="store_true",
        help="Legacy 1/9/15: disable automatic nearby source-oracle lookup",
    )
    ap.add_argument("--dump-entries", action="store_true", help="Compact v2: dump per-entry payload/key blobs")
    return ap


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_argparser().parse_args(argv)
    args.auto_source_oracle = not args.no_auto_source_oracle
    if args.interactive or not args.inputs:
        if not sys.stdin.isatty():
            raise SystemExit("interactive mode requires a TTY")
        print("note: interactive mode uses the offline heuristic extractor.")
        args = _interactive_args(args)

    for i, path in enumerate(_iter_inputs(args.inputs)):
        if i:
            print()
        path = Path(os.path.expanduser(str(path)))
        data = path.read_bytes()
        kind, ver = _detect_container(data)
        if kind == "bom_v3":
            _handle_bom_v3(path, args)
            continue
        if kind == "compact_ysgp" and ver is not None:
            _handle_compact(path, ver, args)
            continue
        print(f"file: {path}")
        print("container: unknown")
        print("status: unsupported")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
