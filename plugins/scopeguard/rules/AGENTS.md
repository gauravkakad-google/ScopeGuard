# ScopeGuard IAM Governance Plugin Rules

When executing any skill in the `scopeguard` plugin (`scopeguard-orchestrator` or any individual `gcp-iam-*` skill), follow these mandatory operational rules:

1. **Mandatory Pre-Req Checks (GCS Assessment Store & Required GCP APIs)**:
   - Every ScopeGuard skill script automatically verifies **both** GCS bucket configuration/reachability and required GCP APIs (`cloudresourcemanager`, `iam`, `recommender`, `logging`, `orgpolicy`, and `securitycenter` when `--fetch-live-scc` is set) before executing IAM scans.
   - **First Run (`exit code 20` — `BUCKET_CONFIG_REQUIRED`)**: Do NOT guess or silently create a bucket. Prompt the user to confirm:
     - **GCS Bucket Name** (default: `<project_id>_scopeguard_assessments`, or user-specified custom bucket name)
     - **GCS Region** (default: `asia-southeast1`, or user-specified custom region)
   - **Missing Bucket (`exit code 21` — `BUCKET_NOT_FOUND`)**: Ask the user for confirmation before passing `--ensure-bucket --save-bucket-config`.
   - **Disabled Required GCP APIs (`exit code 23` — `APIS_ENABLEMENT_REQUIRED`)**: Do NOT auto-enable APIs silently. Present the exact list of missing APIs and their purpose from the JSON output and ask the user whether to:
     - Enable them now (re-run with `--ensure-apis`), OR
     - Proceed in degraded mode without enabling them (re-run with `--skip-api-check`).
   - **Subsequent Runs**: Do NOT re-prompt once `~/.scopeguard/config.json` is saved and required APIs are enabled—all skills automatically reuse the saved bucket and write to `gs://<saved_bucket>/<target_project_id>/runs/<UTC_timestamp>_<mode>_<id>.json` + `<target_project_id>/latest.json`.

2. **Human-in-the-Loop IAM Safety Gate**:
   - All ScopeGuard skills operate strictly in **read-only assessment and IaC/runbook generation mode**.
   - Never autonomously apply IAM policy changes (`set-iam-policy`, `add-iam-policy-binding`, `remove-iam-policy-binding`), disable Service Accounts, or delete keys without explicit user authorization.

3. **Execution Modes**:
   - Use `scopeguard-orchestrator` (`scopeguard_pipeline.py --stages=all`) when the user requests a full end-to-end project assessment.
   - Invoke the specific individual `gcp-iam-*` skill when the user asks for a targeted task; carried-forward sibling modules in GCS are automatically marked as `CARRIED_FORWARD_PROBABLY_STALE` or `STALE_POLICY_DRIFT`.

4. **Mandatory Post-Execution Detailed Recommendations (Option A — Automatic Side-Pane Artifact + Chat Action Plan)**:
   - **NEVER** finish a ScopeGuard run by only stating that the script succeeded or uploaded to GCS. Without waiting for a follow-up prompt, you **MUST ALWAYS** do both of the following at the end of every full-suite or standalone skill run:
     1. **Publish a Full Detailed Recommendations Artifact**: Read `scopeguard_recommendations_<project_id>.md` generated in `--output-dir` (and any skill-specific report) and write a user-facing Antigravity Artifact (`<artifact_dir>/scopeguard_recommendations_<project_id>.md` via `write_file` with `ArtifactMetadata: {UserFacing: true, RequestFeedback: false, Summary: "..."}`, `Overwrite: true`) containing the complete principal-by-principal tables, custom role specs, PAM/WIF/Deny/Terraform guidance, compliance delta, and rollback commands so it opens automatically in the Antigravity Artifact side pane.
     2. **Present an Executive & Phased Action Summary Directly in Chat**: Using `recommendation_digest` returned in CLI `stdout`, output a concise, structured summary in chat covering:
        - **Key Posture & Risk-Reduction KPIs** (permissions before vs. after, simulated HTTP 403s, compliance score delta, PAM/WIF/Deny counts)
        - **Prioritized `P0` $\rightarrow$ `P3` Recommendations** naming specific principals, roles, and actions (explicitly noting any `CARRIED_FORWARD_PROBABLY_STALE` modules on partial runs)
        - **Clickable Links** to the Side-Pane Recommendations Artifact, generated `.tf`/`.yaml`/`.sh` deliverables (`file://`), and the published GCS snapshot / Stateless Viewer URL.

5. **Live Chat Progress for Org / Folder Sweeps (Portable Across `agy` CLI, Antigravity IDE & Claude Code)**:
   - When the user asks to sweep a GCP Organization (`--org-id`) or Folder (`--folder-id`), **prefer interactive project-by-project orchestration** so the user sees live progress directly in the chat/CLI instead of waiting silently on a single long background command:
     1. Run `scopeguard_pipeline.py --org-id=<ID> --discover-only` (or `--folder-id=<ID> --discover-only`) first. This completes in a few seconds, performs the GCS & upfront GCP API preflight (`exit code 23` if any project has disabled APIs), and returns the discovered project list.
     2. Inform the user of the discovered project count and run `scopeguard_pipeline.py --project=<PID>` (with `--skip-api-check` or `--ensure-apis` per the user's preflight choice) for each project, **printing a 1–2 line live progress update in chat after every project completes** (e.g., `Progress [3/10]: ✅ my-gcp-project — 40,608 → 82 perms (-99.8%), 6 escalations | Next: my-analytics-project`).
     3. After all projects complete, run `scopeguard_pipeline.py --org-id=<ID> --finalize-rollup` (or `--folder-id=<ID> --finalize-rollup`) to publish `_scopes/<scope>/latest.json` + Markdown rollup to GCS and present the final fleet summary.
