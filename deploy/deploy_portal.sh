#!/usr/bin/env bash
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
#
# Deploys the ScopeGuard Stateless GCS Review Portal to Cloud Run behind IAP
# using a dedicated bucket-only read-only Service Account (roles/storage.objectViewer).

set -euo pipefail

PROJECT_ID=""
BUCKET=""
REGION="us-central1"
SERVICE_NAME="scopeguard-portal"
SA_NAME="scopeguard-portal-sa"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project=*) PROJECT_ID="${1#*=}"; shift ;;
    --project) PROJECT_ID="$2"; shift 2 ;;
    --bucket=*) BUCKET="${1#*=}"; shift ;;
    --bucket) BUCKET="$2"; shift 2 ;;
    --region=*) REGION="${1#*=}"; shift ;;
    --region) REGION="$2"; shift 2 ;;
    --service-name=*) SERVICE_NAME="${1#*=}"; shift ;;
    --service-name) SERVICE_NAME="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 --project=<HOST_PROJECT_ID> --bucket=<GCS_BUCKET_NAME> [--region=us-central1] [--service-name=scopeguard-portal]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "${PROJECT_ID}" || -z "${BUCKET}" ]]; then
  echo "Error: --project and --bucket are required." >&2
  exit 1
fi

BUCKET="${BUCKET#gs://}"
BUCKET="${BUCKET%/}"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[1/3] Ensuring dedicated zero-trust Service Account (${SA_EMAIL})..."
if ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1; then
  gcloud iam service-accounts create "${SA_NAME}" \
    --display-name="ScopeGuard Stateless GCS Portal (Read-Only)" \
    --project="${PROJECT_ID}" \
    --quiet
fi

echo "[2/3] Granting bucket-only roles/storage.objectViewer on gs://${BUCKET}..."
gcloud storage buckets add-iam-policy-binding "gs://${BUCKET}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/storage.objectViewer" \
  --project="${PROJECT_ID}" \
  --quiet >/dev/null

echo "[3/3] Deploying ${SERVICE_NAME} to Cloud Run (${REGION}) with IAP..."
gcloud run deploy "${SERVICE_NAME}" \
  --source="${REPO_ROOT}" \
  --region="${REGION}" \
  --project="${PROJECT_ID}" \
  --service-account="${SA_EMAIL}" \
  --iap \
  --no-allow-unauthenticated \
  --set-env-vars="SCOPEGUARD_GCS_BUCKET=${BUCKET},SCOPEGUARD_GCS_REGION=${REGION}" \
  --quiet

echo "Deployment complete. Remember to grant IAP-secured Web App User (roles/iap.httpsResourceAccessor) to authorized reviewers."
