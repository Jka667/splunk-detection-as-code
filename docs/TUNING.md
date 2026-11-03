# Tuning workflow (IR requests)

1. **Intake** – IR opens a Jira ticket: detection ID, alert examples (notable IDs), what is noisy or missed.
2. **Triage** – Reproduce with the detection SPL over 7–30 days. Classify every hit: true positive,
   benign true positive (expected activity), false positive (logic error).
3. **Change** – Pick the narrowest fix:
   - logic error → fix the SPL (field, operator, regex);
   - benign activity → exclusion on a stable attribute (signed binary path, service account, scanner IP lookup), never on a hostname alone;
   - volume → threshold / time window, documented with the before/after counts.
4. **Validate** – Re-run the original true positive (Atomic test or saved event) and confirm it still fires.
5. **Record** – Add a `tuning` entry in the YAML and link the PR in Jira:

```yaml
tuning:
  - date: 2026-11-03
    ticket: DET-12
    change: Excluded ParentImage "*\\IntuneManagementExtension\\*"
    reason: "Intune scripts, 340 alerts/week, 0 TP over 30 days"
    validation: Atomic T1059.001 still detected
```

6. **Coverage gaps** – Anything we cannot detect goes in `dist/COVERAGE.md` follow-up as a new Jira ticket.
