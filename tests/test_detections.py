import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from build import attack_layer, savedsearch  # noqa: E402
from validate import load_all, validate  # noqa: E402


def test_all_detections_valid():
    for path, det in load_all().items():
        assert validate(det) == [], path.name


def test_invalid_detection_is_flagged():
    det = next(iter(load_all().values())) | {"mitre": ["T99"], "status": "stable", "tests": []}
    errors = validate(det)
    assert any("ATT&CK" in e for e in errors)
    assert any("stable" in e for e in errors)
    assert validate(None)


def test_multiline_spl_uses_conf_continuation():
    det = next(iter(load_all().values()))
    conf = savedsearch(det)
    assert conf.startswith(f"[{det['id']} - ")
    assert det["search"].strip().count("\n") == conf.split("\ndescription")[0].count(" \\\n")


def test_layer_counts_techniques():
    layer = attack_layer([{"id": "DET-0001", "mitre": ["T1059.001"]}, {"id": "DET-0002", "mitre": ["T1059.001"]}])
    assert layer["techniques"] == [{"techniqueID": "T1059.001", "score": 2, "comment": "DET-0001, DET-0002"}]
