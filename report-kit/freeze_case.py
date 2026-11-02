#!/usr/bin/env python3
"""Freeze an REPORT case and its source artifacts for a repeatable report build.

The source case is read only. The destination must not exist. Generated reports
are excluded; all files under the case's evidence, transcripts, and code
directories are retained, including files not referenced by an event.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path, PurePosixPath

SOURCE_DIRS = ("evidence", "transcripts", "code")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str):
        raise ValueError("artifact path is not text")
    parts = PurePosixPath(relative)
    if not parts.parts or parts.is_absolute() or ".." in parts.parts or parts.parts[0] not in SOURCE_DIRS:
        raise ValueError(f"artifact path escapes source directories: {relative}")
    path = root.joinpath(*parts.parts)
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
        raise ValueError(f"missing or unsafe artifact: {relative}")
    return path


def freeze(case_dir: Path, destination: Path, redops_archive: Path | None = None) -> dict:
    case_dir = case_dir.resolve(strict=True)
    destination = destination.expanduser().resolve(strict=False)
    if destination.exists():
        raise FileExistsError(f"snapshot already exists: {destination}")
    if destination.is_relative_to(case_dir):
        raise ValueError("snapshot must be outside the live case")
    case_file = case_dir / "case.json"
    if case_file.is_symlink() or not case_file.is_file():
        raise ValueError("case.json is missing or a symlink")
    case = json.loads(case_file.read_text(encoding="utf-8"))
    if case.get("schema") != 1 or not isinstance(case.get("events"), list):
        raise ValueError("unsupported REPORT case")
    source_files: dict[str, Path] = {}
    for folder in SOURCE_DIRS:
        directory = case_dir / folder
        if not directory.exists():
            continue
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"unsafe source directory: {folder}")
        for path in directory.rglob("*"):
            if path.is_symlink():
                raise ValueError(f"symlink in case source: {path.relative_to(case_dir)}")
            if path.is_file():
                relative = path.relative_to(case_dir).as_posix()
                source_files[relative] = source_path(case_dir, relative)
    for event in case["events"]:
        for field in ("transcript", "file"):
            relative = event.get(field)
            if not relative:
                continue
            path = source_path(case_dir, relative)
            source_files[relative] = path
            if event.get("sha256") != sha256(path):
                raise ValueError(f"event {event.get('id')} {field} hash mismatch")
    archive_source = redops_archive.resolve(strict=True) if redops_archive else None
    if archive_source and (archive_source.is_symlink() or not archive_source.is_file()):
        raise ValueError("RedOps archive is not a regular file")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".report-freeze-", dir=destination.parent) as temp_name:
        staging = Path(temp_name)
        os.chmod(staging, 0o700)
        shutil.copyfile(case_file, staging / "case.json")
        os.chmod(staging / "case.json", 0o600)
        inventory = []
        for relative, source in sorted(source_files.items()):
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            os.chmod(target, 0o600)
            inventory.append({"path": relative, "sha256": sha256(target), "bytes": target.stat().st_size})
        if archive_source:
            relative = "redops/engagement-runs.jsonl"
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(archive_source, target)
            os.chmod(target, 0o600)
            inventory.append({"path": relative, "sha256": sha256(target), "bytes": target.stat().st_size})
        inventory.insert(0, {"path": "case.json", "sha256": sha256(staging / "case.json"),
                             "bytes": (staging / "case.json").stat().st_size})
        manifest = {"schema": 1, "files": inventory}
        encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        (staging / "freeze-manifest.json").write_bytes(encoded)
        os.chmod(staging / "freeze-manifest.json", 0o600)
        staging.rename(destination)
    return {"snapshot": str(destination), "case_sha256": inventory[0]["sha256"],
            "manifest_sha256": sha256(destination / "freeze-manifest.json"),
            "file_count": len(inventory),
            "archive_sha256": sha256(destination / "redops/engagement-runs.jsonl") if archive_source else None}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--redops-archive", type=Path)
    args = parser.parse_args()
    print(json.dumps(freeze(args.case, args.out, args.redops_archive), sort_keys=True))


if __name__ == "__main__":
    main()
