"""Import a browser-chat run into a generic RedOps report case.

The runner's raw manifest and artifacts remain authoritative. Each action is
idempotent by run/action ID, and direct screenshots are copied into the case.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

import report


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact(run_dir: Path, rel: str) -> Path:
    path = (run_dir / rel).resolve()
    if not path.is_relative_to(run_dir.resolve()) or not path.is_file():
        raise ValueError(f"missing or outside-run artifact: {rel}")
    return path


def import_run(case_dir: Path, target: str, stage: str, manifest_path: Path) -> list[str]:
    manifest_path = manifest_path.resolve()
    run_dir = manifest_path.parent
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "redops-webchat-v1":
        raise ValueError("unsupported webchat manifest")
    run_id = str(manifest.get("run_id") or "")
    if not run_id or not isinstance(manifest.get("events"), list):
        raise ValueError("run_id and events required")
    imported = []
    with report.case_lock(case_dir):
        data = report.load(case_dir)
        report.stage(data, target, stage)
        for item in manifest["events"]:
            action_id = str(item.get("id") or "")
            if not action_id:
                raise ValueError("event id required")
            key = f"webchat:{run_id}:{action_id}"
            input_text = json.dumps(item.get("input"), ensure_ascii=False, sort_keys=True)
            output_text = str(item.get("output") or "")
            network_source = artifact(run_dir, str(item["network_path"]))
            network_hash = sha256(network_source)
            screenshot_source = artifact(run_dir, str(item["screenshot_path"]))
            screenshot_hash = sha256(screenshot_source)
            stated = item.get("artifact_hashes") or {}
            if stated and (stated.get("network") != network_hash or
                           stated.get("screenshot") != screenshot_hash):
                raise ValueError(f"artifact hash mismatch: {key}")
            prior = next((e for e in data["events"] if e.get("source_key") == key), None)
            if prior:
                if (prior.get("target") != target or prior.get("stage") != stage or
                    prior.get("text") != input_text or prior.get("result") != output_text or
                    prior.get("sha256") != network_hash or
                    prior.get("screenshot_sha256") != screenshot_hash):
                    raise ValueError(f"changed reimport: {key}")
                imported.append(prior["id"])
                continue
            network_dest = case_dir / "transcripts" / f"{report.ident()}-webchat.jsonl"
            network_dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(network_source, network_dest)
            shot_dest = case_dir / "evidence" / f"{report.ident()}-webchat.png"
            shot_dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(screenshot_source, shot_dest)
            event = {
                "target": target, "stage": stage, "kind": "browser",
                "text": input_text, "result": output_text,
                "source_key": key, "source_system": "webchat",
                "source_recorded_at": str(item.get("at") or ""),
                "page_url": manifest.get("page_url"),
                "conversation_id": item.get("conversation_id"),
                "transcript": str(network_dest.relative_to(case_dir)),
                "sha256": network_hash,
                "screenshot_sha256": screenshot_hash,
            }
            eid = report.add_event(case_dir, data, event, actor="webchat-recorder")
            report.add_event(case_dir, data, {
                "target": target, "stage": stage, "kind": "screenshot",
                "role": "evidence", "provenance": "direct_import",
                "caption": f"Chatbot after {item.get('type', 'interaction')} {action_id}",
                "file": str(shot_dest.relative_to(case_dir)),
                "sha256": screenshot_hash,
                "source_key": key + ":screenshot",
            }, actor="webchat-recorder")
            imported.append(eid)
    return imported


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--stage", required=True)
    args = parser.parse_args()
    print("\n".join(import_run(args.case.resolve(), args.target, args.stage, args.manifest)))


if __name__ == "__main__":
    main()
