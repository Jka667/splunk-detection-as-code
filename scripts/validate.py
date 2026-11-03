"""Validate every detection YAML file. Exits 1 on any error (used by CI)."""
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = ["id", "name", "status", "severity", "mitre", "data_sources", "description",
            "search", "schedule", "false_positives", "tests"]
SEVERITIES = {"low", "medium", "high", "critical"}
STATUSES = {"experimental", "stable", "deprecated"}
TEST_TYPES = {"atomic", "stratus", "caldera", "manual"}
DET_ID = re.compile(r"^DET-\d{4}$")
ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def validate(det):
    det = det or {}
    errors = [f"missing field: {k}" for k in REQUIRED if k not in det]
    if errors:
        return errors
    if not DET_ID.match(str(det["id"])):
        errors.append(f"bad id: {det['id']}")
    if det["status"] not in STATUSES:
        errors.append(f"bad status: {det['status']}")
    if det["severity"] not in SEVERITIES:
        errors.append(f"bad severity: {det['severity']}")
    if not det["mitre"] or any(not ATTACK_ID.match(str(t)) for t in det["mitre"]):
        errors.append(f"bad ATT&CK ids: {det['mitre']}")
    if not str(det["search"]).strip():
        errors.append("empty search")
    if not {"cron", "earliest", "latest"} <= set(det["schedule"] or {}):
        errors.append("schedule needs cron, earliest, latest")
    if any(t.get("type") not in TEST_TYPES for t in det["tests"] or []):
        errors.append(f"test type must be one of {sorted(TEST_TYPES)}")
    if det["status"] == "stable" and not det["tests"]:
        errors.append("stable detections need at least one validation test")
    return errors


def load_all(directory=ROOT / "detections"):
    return {p: yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted(directory.glob("*.yml"))}


def main():
    detections = load_all()
    failed, seen = False, {}
    for path, det in detections.items():
        errors = validate(det)
        det_id = (det or {}).get("id")
        if det_id in seen:
            errors.append(f"duplicate id with {seen[det_id].name}")
        seen[det_id] = path
        for e in errors:
            print(f"{path.name}: {e}")
            failed = True
    print(f"{len(detections)} detections checked: {'FAILED' if failed else 'OK'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
