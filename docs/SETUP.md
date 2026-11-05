# Splunk Detection-as-Code

Splunk detections managed as code: each rule is a YAML file with its SPL, MITRE ATT&CK mapping,
data sources, false positives, tuning history and validation tests. CI validates every rule and
builds a deployable `savedsearches.conf`, an ATT&CK Navigator layer and a coverage report.

## Layout

```
detections/          one YAML file per detection (DET-XXXX)
scripts/validate.py  schema + ATT&CK ID checks (fails CI on error)
scripts/build.py     -> dist/savedsearches.conf, dist/attack_layer.json, dist/COVERAGE.md
tests/               pytest checks
docs/TUNING.md       how IR tuning requests become rule changes
```

## Detections

| ID | Detection | ATT&CK | Telemetry |
|----|-----------|--------|-----------|
| DET-0001 | Encoded PowerShell command | T1059.001, T1027 | Sysmon EID 1 |
| DET-0002 | Suspicious LSASS memory access | T1003.001 | Sysmon EID 10 |
| DET-0003 | Scheduled task created | T1053.005 | Windows Security 4698 |
| DET-0004 | Office application spawning a shell | T1204.002, T1566.001 | Sysmon EID 1 |
| DET-0005 | Security event log cleared | T1070.001 | Windows Security 1102 |
| DET-0006 | SSH brute force | T1110.001 | Linux auth logs |
| DET-0007 | AWS console login without MFA | T1078.004 | AWS CloudTrail |
| DET-0008 | AWS access key created for another user | T1098.001 | AWS CloudTrail |
| DET-0009 | Network activity matching CTI IOCs | T1071 | Sysmon EID 3 / 22 + CTI lookup |

The CTI lookup used by DET-0009 is produced by [cti-stix-to-splunk](https://github.com/Jka667/cti-stix-to-splunk).
Rules are validated in the [purple-team-lab](https://github.com/Jka667/purple-team-lab).

## Usage

```bash
pip install -r requirements.txt
python scripts/validate.py
python scripts/build.py
pytest
```

Deploy: copy `dist/savedsearches.conf` into `$SPLUNK_HOME/etc/apps/<your_app>/local/` and restart Splunk
(or use the REST API / your deployment server).

## Workflow

1. Every change starts from a Jira ticket (`DET-123`): IR tuning request, CTI report, or purple team gap.
2. Branch `DET-123-short-description`, edit the YAML, add a `tuning` entry with the rationale.
3. Validate in Splunk (true positive confirmed, noise measured over 7 days) and paste the evidence in the PR.
4. CI must pass; merge; deploy `dist/savedsearches.conf`; close the Jira ticket with the PR link.

## Detection schema

```yaml
id: DET-0001                 # unique, DET-XXXX
name: ...
status: stable               # experimental | stable | deprecated (experimental = deployed disabled)
severity: high               # low | medium | high | critical
mitre: [T1059.001]
data_sources: [sysmon]
description: ...
search: |                    # SPL
  index=sysmon EventCode=1 ...
schedule: {cron: "*/15 * * * *", earliest: -20m, latest: now}
false_positives: [...]
tuning:                      # change log, one entry per adjustment
  - {date: 2026-11-03, ticket: DET-12, change: ..., reason: ...}
tests:                       # required for stable rules
  - {type: atomic, technique: T1059.001, test_name: ...}
```
