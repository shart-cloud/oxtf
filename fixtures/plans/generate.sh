#!/usr/bin/env bash
# Regenerates fixtures/plans/<rule>/<case>[__<variant>].json from the W4 rule
# fixtures (fixtures/rules/<rule>/<case>/) with `terraform plan` + `terraform
# show -json`, offline, with fake provider credentials.
#
# Each case is copied to $WORK/<rule>/<case>[__variant]/ (the fixtures are not
# edited); a provider file (zz_w5_providers.tf) is added there with
# required_providers pinned to the versions in the plugin cache and provider
# blocks that skip every credential / account / metadata check.
# `conditional_*` cases have a variable with no value; terraform requires one,
# so they are planned twice: `__fail` (an insecure value) and `__pass` (a
# secure value). See VARS below.
#
# Plan-only cases in fixtures/plan_cases/<case>/ are planned into
# fixtures/plan_cases/<case>/plan.json (PLAN_CASES_ONLY=1 does only those).
#
# Usage: fixtures/plans/generate.sh [WORK_DIR]   (default /tmp/claude-0/w5)
# Needs: terraform 1.16.x on PATH, providers in /opt/tftools/plugin-cache.
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
WORK=${1:-/tmp/claude-0/w5}
PLUGIN_DIR=${PLUGIN_DIR:-/opt/tftools/plugin-cache}
OUT="$REPO/fixtures/plans"

# -var values for the conditional cases: "<rule>/<case> <variant> <var>=<value>"
VARS=(
  "aws-rds-unencrypted/conditional_unconstrained_variable fail encrypt=false"
  "aws-rds-unencrypted/conditional_unconstrained_variable pass encrypt=true"
  "aws-s3-public-access-block/conditional_unconstrained_variable fail block_public=false"
  "aws-s3-public-access-block/conditional_unconstrained_variable pass block_public=true"
  "aws-sg-open-ssh/conditional_unconstrained_variable fail ssh_cidr=0.0.0.0/0"
  "aws-sg-open-ssh/conditional_unconstrained_variable pass ssh_cidr=10.0.0.0/8"
)

providers_tf() {
  cat <<'TF'
# Added by fixtures/plans/generate.sh (not part of the fixture).
terraform {
  required_providers {
    aws    = { source = "hashicorp/aws", version = "6.68.0" }
    google = { source = "hashicorp/google", version = "8.7.0" }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "x"
  secret_key                  = "x"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}

provider "google" {
  project     = "x"
  region      = "us-central1"
  credentials = file("${path.module}/fake-sa.json")
}
TF
}

# A syntactically valid service-account key with a throwaway RSA key (not a
# real credential; plan of create-only resources does not call the API).
fake_sa() {
  local key
  key=$(openssl genrsa 2048 2>/dev/null | awk '{printf "%s\\n", $0}')
  cat <<JSON
{"type":"service_account","project_id":"x","private_key_id":"0","private_key":"$key","client_email":"x@x.iam.gserviceaccount.com","client_id":"0","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token"}
JSON
}

plan_one() { # <rule> <case> <variant or ""> [-var k=v]
  local rule=$1 case=$2 variant=$3; shift 3
  local name=$case${variant:+__$variant}
  plan_dir "$REPO/fixtures/rules/$rule/$case" "$WORK/$rule/$name" "$OUT/$rule/$name.json" "$@"
  echo "ok $rule/$name"
}

plan_dir() { # <source dir> <work dir> <output json> [terraform plan args]
  local src=$1 dir=$2 out=$3; shift 3
  rm -rf "$dir"; mkdir -p "$dir"
  cp -r "$src/." "$dir/"
  rm -f "$dir/plan.json"
  rm -f "$dir/EXPECT"
  providers_tf > "$dir/zz_w5_providers.tf"
  fake_sa > "$dir/fake-sa.json"
  (
    cd "$dir"
    terraform init -input=false -no-color -plugin-dir="$PLUGIN_DIR" >init.log 2>&1 \
      || { cat init.log; exit 1; }
    terraform plan -input=false -no-color -refresh=false -out=tfplan "$@" >plan.log 2>&1 \
      || { cat plan.log; exit 1; }
    terraform show -json tfplan > plan.json
  )
  mkdir -p "$(dirname "$out")"
  # Pretty-print with sorted keys for stable diffs.
  python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])), indent=1, sort_keys=True))' \
    "$dir/plan.json" > "$out"
}

# Plan-only cases: fixtures/plan_cases/<case>/ (source) -> <case>/plan.json.
for src in "$REPO"/fixtures/plan_cases/*/; do
  src=${src%/}; case=$(basename "$src")
  plan_dir "$src" "$WORK/plan_cases/$case" "$src/plan.json"
  echo "ok plan_cases/$case"
done
[[ ${PLAN_CASES_ONLY:-0} == 1 ]] && exit 0

cd "$REPO/fixtures/rules"
for case_dir in */*/; do
  case_dir=${case_dir%/}
  rule=${case_dir%%/*}; case=${case_dir#*/}
  if [[ $case == conditional_* ]]; then
    for line in "${VARS[@]}"; do
      read -r key variant kv <<<"$line"
      [[ $key == "$rule/$case" ]] && plan_one "$rule" "$case" "$variant" -var "$kv"
    done
  else
    plan_one "$rule" "$case" ""
  fi
done
