"""Build dist/savedsearches.conf, dist/attack_layer.json and dist/COVERAGE.md from detections/."""
import json
import sys

from validate import ROOT, load_all, validate

SPLUNK_SEVERITY = {"low": 3, "medium": 4, "high": 5, "critical": 6}


def savedsearch(det):
    # .conf values continue on the next line when a line ends with a backslash
    search = " \\\n".join(det["search"].strip().splitlines())
    s = det["schedule"]
    return "\n".join([
        f"[{det['id']} - {det['name']}]",
        f"search = {search}",
        f"description = {' '.join(det['description'].split())} | ATT&CK: {', '.join(det['mitre'])}",
        f"disabled = {1 if det['status'] == 'experimental' else 0}",
        "enableSched = 1",
        f"cron_schedule = {s['cron']}",
        f"dispatch.earliest_time = {s['earliest']}",
        f"dispatch.latest_time = {s['latest']}",
        "counttype = number of events",
        "relation = greater than",
        "quantity = 0",
        "alert.track = 1",
        f"alert.severity = {SPLUNK_SEVERITY[det['severity']]}",
    ])


def attack_layer(dets):
    techniques = {}
    for d in dets:
        for t in d["mitre"]:
            techniques.setdefault(t, []).append(d["id"])
    return {
        "name": "Splunk detection coverage",
        "domain": "enterprise-attack",
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "techniques": [{"techniqueID": t, "score": len(ids), "comment": ", ".join(ids)}
                       for t, ids in sorted(techniques.items())],
        "gradient": {"colors": ["#c6dbef", "#08519c"], "minValue": 0, "maxValue": 3},
    }


def coverage_md(dets):
    lines = ["# Detection coverage", "", "| ID | Name | Status | ATT&CK | Data sources | Tests |",
             "|----|------|--------|--------|--------------|-------|"]
    for d in dets:
        lines.append(f"| {d['id']} | {d['name']} | {d['status']} | {', '.join(d['mitre'])} | "
                     f"{', '.join(d['data_sources'])} | {len(d['tests'] or [])} |")
    return "\n".join(lines) + "\n"


def main():
    dets = [d for d in load_all().values() if d and d.get("status") != "deprecated"]
    if any(validate(d) for d in dets):
        print("validation failed, run scripts/validate.py")
        return 1
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    (dist / "savedsearches.conf").write_text("\n\n".join(savedsearch(d) for d in dets) + "\n", encoding="utf-8")
    (dist / "attack_layer.json").write_text(json.dumps(attack_layer(dets), indent=2), encoding="utf-8")
    (dist / "COVERAGE.md").write_text(coverage_md(dets), encoding="utf-8")
    print(f"built {len(dets)} detections into {dist}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
