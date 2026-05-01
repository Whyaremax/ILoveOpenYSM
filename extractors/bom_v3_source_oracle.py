from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from extractors.bom_v3_payload_assets import _read_property_format, _read_property_name, _sanitize_name, parse_property_assets
from extractors.ysgp_container_scanner import scan_file


@dataclass(frozen=True)
class OracleMatch:
    tag: str
    label: str
    hash_hex: str
    source_relpath: str | None
    export_name: str


@dataclass(frozen=True)
class OracleSourceEntry:
    source_relpath: str
    data: bytes


@dataclass(frozen=True)
class OracleRestoreSummary:
    out_dir: Path
    source_root: Path
    match_count: int
    asset_count: int
    status: str
    matched_assets: tuple[OracleMatch, ...]
    unmatched_assets: tuple[OracleMatch, ...]

    @property
    def exact_complete(self) -> bool:
        return self.asset_count > 0 and self.match_count == self.asset_count


@dataclass(frozen=True)
class OracleCandidateSummary:
    source_root: Path
    search_depth: int
    match_count: int
    asset_count: int

    @property
    def exact_complete(self) -> bool:
        return self.asset_count > 0 and self.match_count == self.asset_count

    @property
    def readiness(self) -> str:
        if self.match_count <= 0:
            return "no oracle"
        if self.exact_complete:
            return "exact-complete"
        return "partial"


def _iter_source_entries(source_root: Path) -> Iterable[OracleSourceEntry]:
    if source_root.is_dir():
        for path in source_root.rglob("*"):
            if not path.is_file():
                continue
            yield OracleSourceEntry(str(path.relative_to(source_root)).replace("\\", "/"), path.read_bytes())
        return
    if source_root.is_file() and zipfile.is_zipfile(source_root):
        with zipfile.ZipFile(source_root) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                yield OracleSourceEntry(info.filename.replace("\\", "/"), zf.read(info))
        return
    raise ValueError(f"unsupported source oracle candidate: {source_root}")


def _build_hash_to_entry(source_root: Path) -> dict[str, OracleSourceEntry]:
    hash_to_entry: dict[str, OracleSourceEntry] = {}
    for entry in _iter_source_entries(source_root):
        hash_to_entry[hashlib.sha256(entry.data).hexdigest()] = entry
    return hash_to_entry


def _property_assets(ysm_path: Path):
    return tuple(parse_property_assets(scan_file(ysm_path, dump=False).property_text))


def _is_source_tree_candidate(path: Path) -> bool:
    try:
        if not path.is_dir():
            return False
    except (OSError, PermissionError):
        return False
    if path.name.startswith("."):
        return False
    try:
        if (path / "oracle_restore.json").exists():
            return False
        if (path / "legacy_sections.json").exists():
            return False
    except (OSError, PermissionError):
        return False
    markers = (
        path / "models",
        path / "animations",
        path / "textures",
        path / "sounds",
        path / "avatar",
        path / "ysm.json",
    )
    try:
        return any(marker.exists() for marker in markers)
    except (OSError, PermissionError):
        return False


def _is_source_archive_candidate(path: Path) -> bool:
    try:
        return path.is_file() and path.suffix.lower() == ".zip" and zipfile.is_zipfile(path)
    except (OSError, PermissionError, zipfile.BadZipFile):
        return False


def default_export_dir(ysm_path: Path) -> Path:
    folder_name = _sanitize_name(_read_property_name(ysm_path) or ysm_path.stem)
    codec_format = _read_property_format(ysm_path)
    out_dir = ysm_path.with_name(folder_name)
    if out_dir.exists() and codec_format is not None:
        out_dir = ysm_path.with_name(f"{folder_name}_format{codec_format}")
    return out_dir


def _default_search_roots(ysm_path: Path) -> list[Path]:
    roots: list[Path] = []
    for root in (ysm_path.parent, ysm_path.parent.parent):
        if root not in roots:
            roots.append(root)
    return roots


def _candidate_sort_key(summary: OracleCandidateSummary) -> tuple[int, int, int, str]:
    return (-summary.match_count, summary.search_depth, len(summary.source_root.parts), str(summary.source_root))


def _iter_nearby_candidates(
    root: Path,
    *,
    include_archives: bool,
    max_depth: int = 3,
) -> Iterable[tuple[Path, int]]:
    seen: set[Path] = set()
    pending: list[tuple[Path, int]] = [(root, 0)]
    while pending:
        current, depth = pending.pop(0)
        try:
            current_key = current.resolve()
        except Exception:
            current_key = current
        if current_key in seen:
            continue
        seen.add(current_key)

        if _is_source_tree_candidate(current):
            yield current, depth
        elif include_archives and _is_source_archive_candidate(current):
            yield current, depth

        if depth >= max_depth:
            continue
        try:
            is_dir = current.is_dir()
        except (OSError, PermissionError):
            continue
        if not is_dir:
            continue
        try:
            children = sorted(current.iterdir(), key=lambda item: item.name.lower())
        except (OSError, PermissionError):
            continue
        for child in children:
            if child.name.startswith("."):
                continue
            pending.append((child, depth + 1))


def _count_candidate_matches(assets, source_root: Path, *, search_depth: int) -> OracleCandidateSummary:
    hash_to_entry = _build_hash_to_entry(source_root)
    match_count = sum(1 for asset in assets if asset.hash_hex in hash_to_entry)
    return OracleCandidateSummary(
        source_root=source_root,
        search_depth=search_depth,
        match_count=match_count,
        asset_count=len(assets),
    )


def rank_source_oracle_candidates(
    ysm_path: Path,
    search_roots: Iterable[Path] | None = None,
    *,
    include_archives: bool = False,
) -> list[OracleCandidateSummary]:
    assets = _property_assets(ysm_path)
    if not assets:
        return []

    roots = list(search_roots) if search_roots is not None else _default_search_roots(ysm_path)
    seen: set[Path] = set()
    summaries: list[OracleCandidateSummary] = []
    for root in roots:
        if not root.exists():
            continue
        for candidate, depth in _iter_nearby_candidates(root, include_archives=include_archives):
            try:
                candidate_key = candidate.resolve()
            except Exception:
                candidate_key = candidate
            if candidate_key in seen:
                continue
            seen.add(candidate_key)
            summary = _count_candidate_matches(assets, candidate, search_depth=depth)
            if summary.match_count > 0:
                summaries.append(summary)
    summaries.sort(key=_candidate_sort_key)
    return summaries


def inspect_source_oracle(
    ysm_path: Path,
    source_root: Path | None = None,
    search_roots: Iterable[Path] | None = None,
    *,
    include_archives: bool = False,
) -> OracleCandidateSummary | None:
    if source_root is not None:
        assets = _property_assets(ysm_path)
        return _count_candidate_matches(assets, source_root.resolve(), search_depth=0)
    ranked = rank_source_oracle_candidates(
        ysm_path,
        search_roots=search_roots,
        include_archives=include_archives,
    )
    return ranked[0] if ranked else None


def find_best_source_oracle(
    ysm_path: Path,
    search_roots: Iterable[Path] | None = None,
    *,
    include_archives: bool = False,
) -> tuple[Path | None, int, int]:
    assets = _property_assets(ysm_path)
    if not assets:
        return (None, 0, 0)
    ranked = rank_source_oracle_candidates(
        ysm_path,
        search_roots=search_roots,
        include_archives=include_archives,
    )
    if not ranked:
        return (None, 0, len(assets))
    best = ranked[0]
    return (best.source_root, best.match_count, best.asset_count)


def _canonical_name(tag: str, label: str, source_path: Path | None) -> str:
    tag = tag.lower()
    label = label.lower()
    ext = source_path.suffix if source_path is not None else ""
    if tag in ("main_model", "model_main"):
        return "main.json"
    if tag in ("arm_model", "model_arm"):
        return "arm.json"
    if tag in ("arrow_model",):
        return "arrow.json"
    if tag == "model":
        return f"model{ext or '.bin'}"
    if tag in ("main_animation", "animation_main"):
        return "main.animation.json"
    if tag == "arm_animation":
        return "arm.animation.json"
    if tag == "extra_animation":
        return "extra.animation.json"
    if tag == "tac_animation":
        return "tac.animation.json"
    if tag == "carryon_animation":
        return "carryon.animation.json"
    if tag == "arrow_animation":
        return "arrow.animation.json"
    if tag == "tlm_animation":
        return "tlm.animation.json"
    if tag.startswith("texture_"):
        return f"{tag[len('texture_'):]}{ext or '.png'}"
    if tag == "arrow_texture":
        return f"arrow{ext or '.png'}"
    if tag == "texture":
        name = label or "texture"
        return f"{name}{ext or '.png'}"
    if tag.endswith((".png", ".jpg", ".jpeg", ".tga")):
        return f"texture{ext or Path(tag).suffix or '.png'}"
    if tag.startswith("sound_"):
        return f"{tag[len('sound_'):]}{ext or '.ogg'}"
    if tag == "sound":
        name = label or "sound"
        return f"{name}{ext or '.ogg'}"
    base = tag if not label else f"{tag}_{label}"
    return f"{base}{ext or '.bin'}"


def _source_basename(entry: OracleSourceEntry) -> str:
    name = Path(entry.source_relpath).name
    return name or _sanitize_name(entry.source_relpath.replace("/", "_"))


def _clear_output_dir(out_dir: Path) -> None:
    for pattern in (
        "*.json",
        "*.png",
        "*.ogg",
        "*.bin",
        "*.section.bin",
        "*.manifest.json",
        "*.decompiled.json",
        "property.txt",
        "decoded.bin",
        "asset_bundle.json",
        "oracle_restore.json",
    ):
        for path in out_dir.glob(pattern):
            path.unlink(missing_ok=True)


def restore_from_source_oracle(
    ysm_path: Path,
    source_root: Path,
    out_dir: Path | None = None,
    *,
    clean: bool = False,
    prefer_source_filenames: bool = False,
) -> OracleRestoreSummary:
    assets = _property_assets(ysm_path)
    hash_to_entry = _build_hash_to_entry(source_root)

    if out_dir is None:
        out_dir = ysm_path.with_name(
            f"{_sanitize_name(_read_property_name(ysm_path) or ysm_path.stem)}_oracle_restore_format"
            f"{_read_property_format(ysm_path) or 'unknown'}"
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    if clean:
        _clear_output_dir(out_dir)
    old_manifest = out_dir / "oracle_restore.json"
    if old_manifest.exists():
        try:
            old_obj = json.loads(old_manifest.read_text(encoding="utf-8"))
            for entry in old_obj.get("assets", []):
                export_name = entry.get("export_name")
                if isinstance(export_name, str):
                    (out_dir / export_name).unlink(missing_ok=True)
        except Exception:
            pass

    property_text = scan_file(ysm_path, dump=False).property_text
    (out_dir / "property.txt").write_text(property_text, encoding="utf-8")

    matches: list[OracleMatch] = []
    matched_tags: set[str] = set()
    exported_names: set[str] = set()
    used_names: dict[str, int] = {}
    for asset in assets:
        src = hash_to_entry.get(asset.hash_hex)
        if prefer_source_filenames and src is not None:
            export_name = _source_basename(src)
        else:
            export_name = _canonical_name(asset.tag, asset.label, Path(src.source_relpath) if src is not None else None)
        count = used_names.get(export_name, 0) + 1
        used_names[export_name] = count
        if count > 1:
            stem = Path(export_name).stem
            suffix = Path(export_name).suffix
            export_name = f"{stem}.{count}{suffix}"
        matches.append(
            OracleMatch(
                tag=asset.tag,
                label=asset.label,
                hash_hex=asset.hash_hex,
                source_relpath=src.source_relpath if src is not None else None,
                export_name=export_name,
            )
        )
        if src is not None:
            matched_tags.add(asset.tag.lower())
            (out_dir / export_name).write_bytes(src.data)
            exported_names.add(export_name)

    if any(tag.startswith("texture") or tag == "arrow_texture" for tag in matched_tags):
        for stale_name in ("texture.png", "texture.2.png"):
            if stale_name not in exported_names:
                (out_dir / stale_name).unlink(missing_ok=True)
    if any(tag.startswith("sound_") for tag in matched_tags):
        for stale in out_dir.glob("legacy.*.audio.ogg"):
            if stale.name not in exported_names:
                stale.unlink(missing_ok=True)

    matched_assets = tuple(match for match in matches if match.source_relpath is not None)
    unmatched_assets = tuple(match for match in matches if match.source_relpath is None)
    match_count = len(matched_assets)
    asset_count = len(matches)
    status = "no oracle" if match_count == 0 else "exact-complete" if match_count == asset_count and asset_count > 0 else "partial"
    codec_format = _read_property_format(ysm_path)
    manifest = {
        "source_file": str(ysm_path),
        "source_root": str(source_root),
        "chosen_source_root": str(source_root),
        "codec_format": codec_format,
        "status": status,
        "match_count": match_count,
        "matched_asset_count": match_count,
        "asset_count": asset_count,
        "unmatched_asset_count": len(unmatched_assets),
        "exact_restore_complete": match_count == asset_count and asset_count > 0,
        "matched_assets": [asdict(item) for item in matched_assets],
        "unmatched_assets": [asdict(item) for item in unmatched_assets],
        "assets": [asdict(item) for item in matches],
    }
    (out_dir / "oracle_restore.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return OracleRestoreSummary(
        out_dir=out_dir,
        source_root=source_root,
        match_count=match_count,
        asset_count=asset_count,
        status=status,
        matched_assets=matched_assets,
        unmatched_assets=unmatched_assets,
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Restore exact source files from a YSM property-hash oracle")
    ap.add_argument("ysm_path", type=Path)
    ap.add_argument("source_root", type=Path)
    args = ap.parse_args()
    out = restore_from_source_oracle(args.ysm_path, args.source_root)
    print(out.out_dir)


if __name__ == "__main__":
    main()
