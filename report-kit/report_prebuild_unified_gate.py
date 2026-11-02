#!/usr/bin/env python3
"""Check REPORT evidence integrity before building a report.

The report is a full-fidelity record. This gate never inspects or changes the
meaning of captured bytes. It verifies that every indexed artifact is present,
inside the case directory, and identical to the hash recorded in the ledger.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _artifact(root: Path, event: dict, field: str, blockers: list[dict]) -> None:
    event_id = event.get("id", "<missing>")
    rel = event.get(field)
    if not isinstance(rel, str) or not rel:
        blockers.append({"kind": "artifact-reference-missing", "event_id": event_id,
                         "field": field})
        return
    try:
        path = (root / rel).resolve(strict=True)
    except (OSError, RuntimeError):
        blockers.append({"kind": "artifact-file-missing", "event_id": event_id,
                         "field": field, "path": rel})
        return
    if not path.is_relative_to(root):
        blockers.append({"kind": "artifact-outside-case", "event_id": event_id,
                         "field": field, "path": rel})
        return
    if not path.is_file():
        blockers.append({"kind": "artifact-not-regular-file", "event_id": event_id,
                         "field": field, "path": rel})
        return
    expected = event.get("sha256")
    if not isinstance(expected, str) or len(expected) != 64:
        blockers.append({"kind": "artifact-hash-missing", "event_id": event_id,
                         "field": field, "path": rel})
        return
    actual = digest(path)
    if actual != expected:
        blockers.append({"kind": "artifact-hash-mismatch", "event_id": event_id,
                         "field": field, "path": rel, "actual_sha256": actual})


def evaluate(case, case_json=None, manifest=None, review_list=None) -> dict:
    """Return metadata-only PASS/BLOCK for an REPORT case or frozen snapshot.

    manifest and review_list remain accepted for call-site compatibility. Image
    review is an operator action after report creation; it is not a content
    filter and cannot remove evidence from the report.
    """
    root = Path(case).resolve()
    source = Path(case_json).resolve() if case_json else root / "case.json"
    blockers: list[dict] = []
    warnings: list[dict] = []
    counts = {"events": 0, "artifacts": 0, "screenshots": 0,
              "commands": 0, "code": 0, "unattributed": 0}
    if not root.is_dir():
        blockers.append({"kind": "case-directory-missing", "path": str(root)})
    elif not source.is_file() or not source.is_relative_to(root):
        blockers.append({"kind": "case-json-missing-or-outside", "path": str(source)})
    else:
        try:
            data = json.loads(source.read_bytes())
        except (OSError, UnicodeError, ValueError):
            blockers.append({"kind": "case-json-invalid", "path": str(source)})
            data = None
        if isinstance(data, dict):
            targets = data.get("targets")
            events = data.get("events")
            if not isinstance(targets, dict):
                blockers.append({"kind": "targets-invalid"})
                targets = {}
            if not isinstance(events, list):
                blockers.append({"kind": "events-invalid"})
                events = []
            counts["events"] = len(events)
            by_id: dict[str, dict] = {}
            for index, event in enumerate(events):
                if not isinstance(event, dict):
                    blockers.append({"kind": "event-invalid", "index": index})
                    continue
                event_id = event.get("id")
                if not isinstance(event_id, str) or not event_id:
                    blockers.append({"kind": "event-id-missing", "index": index})
                    continue
                if event_id in by_id:
                    blockers.append({"kind": "event-id-duplicate", "event_id": event_id})
                by_id[event_id] = event
                target = event.get("target")
                if target is None or target == "":
                    counts["unattributed"] += 1
                elif target not in targets:
                    counts["unattributed"] += 1
                    warnings.append({"kind": "event-target-unknown", "event_id": event_id,
                                     "target": str(target)})
                kind = event.get("kind")
                if kind == "command":
                    counts["commands"] += 1
                    if event.get("status") == "done" and not event.get("transcript"):
                        blockers.append({"kind": "command-transcript-missing",
                                         "event_id": event_id})
                elif kind == "screenshot":
                    counts["screenshots"] += 1
                    if event.get("provenance") not in ("direct_import", "rendered_transcript"):
                        warnings.append({"kind": "screenshot-provenance-unknown",
                                         "event_id": event_id})
                elif kind == "code":
                    counts["code"] += 1
                for field in ("transcript", "file"):
                    if event.get(field):
                        counts["artifacts"] += 1
                        _artifact(root, event, field, blockers)
                if kind in ("screenshot", "code") and not event.get("file"):
                    blockers.append({"kind": "event-file-missing", "event_id": event_id})
            for event in events:
                if not isinstance(event, dict) or event.get("kind") != "screenshot":
                    continue
                if event.get("provenance") != "rendered_transcript":
                    continue
                rel = event.get("file", "")
                stem = Path(rel).name.removesuffix("-console.png")
                parent = by_id.get(stem)
                if not rel.endswith("-console.png") or not parent or parent.get("kind") != "command":
                    warnings.append({"kind": "rendered-console-source-unlinked",
                                     "event_id": event.get("id", "<missing>")})
        elif data is not None:
            blockers.append({"kind": "case-json-not-object"})
    if manifest:
        path = Path(manifest).resolve()
        if not path.is_file():
            blockers.append({"kind": "manifest-missing", "path": str(path)})
    return {"case": str(root), "case_json": str(source),
            "status": "BLOCK" if blockers else "PASS",
            "blocker_count": len(blockers), "blockers": blockers,
            "warning_count": len(warnings), "warnings": warnings, "counts": counts}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case_dir")
    parser.add_argument("--case-json")
    parser.add_argument("--manifest")
    parser.add_argument("--review-list", help="accepted for backward compatibility")
    args = parser.parse_args()
    result = evaluate(args.case_dir, args.case_json, args.manifest, args.review_list)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
