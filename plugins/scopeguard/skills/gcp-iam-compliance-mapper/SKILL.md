---
name: gcp-iam-compliance-mapper
description: >-
  Maps Google Cloud IAM posture findings (F1-F7), Service Account key hygiene,
  JIT PAM entitlements, and least-privilege remediation artifacts to CIS Google
  Cloud Platform Foundation Benchmark v3.0, SOC 2 Type II (CC6.1-CC6.3),
  ISO/IEC 27001:2022, and PCI-DSS v4.0 controls. Computes current vs. projected
  post-remediation compliance scores, generates auditor-ready evidence packages,
  and publishes results to the ScopeGuard GCS assessment store.
---

# GCP IAM Regulatory & Compliance Framework Mapper Skill

## Overview

Translates technical IAM posture findings (`F1`–`F7`), Service Account key audits, and least-privilege remediation deliverables into an executive GRC scorecard across four enterprise standards:
- **CIS GCP Foundation Benchmark v3.0** (`1.4`, `1.5`, `1.6`, `1.8`, `1.15`)
- **AICPA SOC 2 Type II** (`CC6.1`, `CC6.2`, `CC6.3`)
- **ISO/IEC 27001:2022** (`A.5.15`, `A.5.18`, `A.8.2`, `A.8.3`)
- **PCI-DSS v4.0** (`Req 7.2.1`, `Req 7.2.2`, `Req 7.2.5`, `Req 8.6.1`)

## Quick Start

```bash
python3 plugins/scopeguard/skills/gcp-iam-compliance-mapper/scripts/compliance_mapper_cli.py \
  --project=my-gcp-project \
  --output-dir=./scopeguard-output/my-gcp-project/compliance
```

Optional `--analysis-json` reuses a local `analysis_results_<project>.json`. Outputs `compliance_matrix.json` and `compliance_evidence_report.md`; evidence references point to `custom-roles/personas/*.yaml` (+ `capabilities/`, `bundles.yaml`), `scopeguard.sarif.json`, and `scc_findings_import.json`.

Runs a `<1s` GCS Assessment Store Pre-Check before execution, reuses `~/.scopeguard/config.json`, writes a new immutable run snapshot under `gs://<bucket>/<project_id>/runs/`, and marks non-executed sibling modules as probably stale.

## Mandatory Post-Execution Output (Option A)

Upon completion, automatically publish `<artifact_dir>/scopeguard_recommendations_<project_id>.md` (`UserFacing: true`) containing the full auditor evidence package and master recommendations, and output the baseline vs. projected compliance scorecards (CIS, SOC 2, ISO 27001, PCI-DSS) and failing-control remediations directly in chat with clickable `file://` links.
