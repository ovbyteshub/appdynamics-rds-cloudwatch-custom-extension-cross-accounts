#!/usr/bin/env bash
set -euo pipefail

REGION="us-east-1"
LOOKBACK_MINUTES=10
PERIOD_SECONDS=60

# The role name that exists in EACH target account
TARGET_ROLE_NAME="AppD_RDSReadRole"

# Account display names in AWS Organizations (NO account IDs here)
ACCOUNT_NAMES=(
  "rds-account-a"
  "rds-account-b"
)

# metricName:stat
METRICS=(
  "CPUUtilization:Average"
  "DatabaseConnections:Average"
  "FreeStorageSpace:Average"
  "FreeableMemory:Average"
  "ReadIOPS:Average"
  "WriteIOPS:Average"
  "ReadLatency:Average"
  "WriteLatency:Average"
)

PREFIX_BASE="Custom Metrics|Amazon RDS|Accounts"
BATCH_SIZE=200

# Logging is disabled by default to keep Machine Agent output clean.
# Enable with: DEBUG=1 LOG_FILE=/tmp/rds-ext.log ./rds-cloudwatch-metrics.sh
DEBUG="${DEBUG:-0}"
LOG_FILE="${LOG_FILE:-/var/log/appd-rds-custom-ext.log}"

log() {
  [[ "$DEBUG" == "1" ]] || return 0
  echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*" >> "$LOG_FILE" 2>/dev/null || true
}

require_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing command: $1" >&2; exit 1; }; }
iso_utc_minutes_ago() { date -u -d "$1 minutes ago" +%Y-%m-%dT%H:%M:%SZ; }

# Always use instance profile for Organizations (management account)
use_instance_profile() {
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_DEFAULT_REGION AWS_REGION
  export AWS_DEFAULT_REGION="$REGION"
}

assume_role() {
  local role_arn="$1" session_name="$2"
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_DEFAULT_REGION AWS_REGION
  aws sts assume-role --role-arn "$role_arn" --role-session-name "$session_name"
}

with_creds_env() {
  local creds_json="$1"
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION
  AWS_ACCESS_KEY_ID=$(echo "$creds_json" | jq -r .Credentials.AccessKeyId)
  AWS_SECRET_ACCESS_KEY=$(echo "$creds_json" | jq -r .Credentials.SecretAccessKey)
  AWS_SESSION_TOKEN=$(echo "$creds_json" | jq -r .Credentials.SessionToken)
  AWS_DEFAULT_REGION="$REGION"
}

list_rds_instances() {
  aws rds describe-db-instances \
    --region "$REGION" \
    --query 'DBInstances[].DBInstanceIdentifier' \
    --output text | tr '\t' '\n' | sed '/^$/d'
}

# CloudWatch query ids must start with a letter and be [A-Za-z0-9_]
cw_id() {
  local s="$1"
  s="$(echo "$s" | tr -c '[:alnum:]' '_' )"
  if [[ ! "$s" =~ ^[A-Za-z] ]]; then s="m_${s}"; fi
  echo "$s"
}

# Build JSON array of MetricDataQueries for one (account, db)
build_queries_json() {
  local account="$1" db="$2"
  local -a queries=()
  local idx=0

  for m in "${METRICS[@]}"; do
    IFS=':' read -r metric_name stat <<< "$m"
    local id
    id="$(cw_id "${account}_${db}_${metric_name}_${idx}")"
    queries+=("{
      \"Id\": \"${id}\",
      \"Label\": \"${metric_name}\",
      \"MetricStat\": {
        \"Metric\": {
          \"Namespace\": \"AWS/RDS\",
          \"MetricName\": \"${metric_name}\",
          \"Dimensions\": [
            {\"Name\":\"DBInstanceIdentifier\",\"Value\":\"${db}\"}
          ]
        },
        \"Period\": ${PERIOD_SECONDS},
        \"Stat\": \"${stat}\"
      },
      \"ReturnData\": true
    }")
    idx=$((idx+1))
  done

  printf '[%s]\n' "$(IFS=,; echo "${queries[*]}")"
}

get_metric_data() {
  local queries_json="$1" start="$2" end="$3"
  aws cloudwatch get-metric-data \
    --metric-data-queries "$queries_json" \
    --start-time "$start" \
    --end-time "$end" \
    --scan-by TimestampDescending \
    --max-datapoints 100 \
    --region "$REGION"
}

require_cmd aws
require_cmd jq

START_TIME="$(iso_utc_minutes_ago "$LOOKBACK_MINUTES")"
END_TIME="$(iso_utc_minutes_ago 0)"

log "Region: ${REGION}"
log "Time window: ${START_TIME} -> ${END_TIME}"
log "Accounts configured (by name): ${#ACCOUNT_NAMES[@]}"
log "Target role name: ${TARGET_ROLE_NAME}"
log "Batch size: ${BATCH_SIZE} queries/request"

OUTPUT_FILE="$(mktemp)"
trap 'rm -f "$OUTPUT_FILE"' EXIT

# ----------------------------
# 1) Resolve ALL account IDs ONCE using management (instance profile)
# ----------------------------
use_instance_profile
log "Fetching accounts list from Organizations (management credentials)..."
ACCOUNTS_JSON="$(aws organizations list-accounts --output json)"

declare -A NAME_TO_ID=()
for name in "${ACCOUNT_NAMES[@]}"; do
  id="$(echo "$ACCOUNTS_JSON" | jq -r --arg n "$name" '.Accounts[] | select(.Name==$n) | .Id' | head -n1)"
  if [[ -z "$id" || "$id" == "null" ]]; then
    log "ERROR: Could not resolve account id for '${name}'. Check Organizations account Name."
    continue
  fi
  NAME_TO_ID["$name"]="$id"
done

# ----------------------------
# 2) For each account: assume role, collect metrics
# ----------------------------
for account_name in "${ACCOUNT_NAMES[@]}"; do
  account_id="${NAME_TO_ID[$account_name]:-}"
  if [[ -z "$account_id" ]]; then
    continue
  fi

  role_arn="arn:aws:iam::${account_id}:role/${TARGET_ROLE_NAME}"
  session_name="rds-batch-${account_name}-$(date +%s)"

  log "Assuming role for '${account_name}' (${account_id}) -> ${role_arn}"
  creds_json="$(assume_role "$role_arn" "$session_name")"
  with_creds_env "$creds_json"

  log "Discovering RDS instances in '${account_name}'..."
  mapfile -t instances < <(list_rds_instances)
  if [[ "${#instances[@]}" -eq 0 ]]; then
    log "No RDS instances found in '${account_name}'."
    continue
  fi

  for db in "${instances[@]}"; do
    full_queries="$(build_queries_json "$account_name" "$db")"
    total_queries="$(echo "$full_queries" | jq 'length')"

    start_idx=0
    while [[ "$start_idx" -lt "$total_queries" ]]; do
      end_idx=$((start_idx + BATCH_SIZE))
      if [[ "$end_idx" -gt "$total_queries" ]]; then end_idx="$total_queries"; fi

      batch_queries="$(echo "$full_queries" | jq ".[$start_idx:$end_idx]")"
      resp="$(get_metric_data "$batch_queries" "$START_TIME" "$END_TIME")"

      # Convert units + force integers:
      # - FreeStorageSpace, FreeableMemory: Bytes -> KB
      # - ReadLatency, WriteLatency: Seconds -> ms
      # - Everything: integer (floor)
      echo "$resp" | jq -r --arg acct "$account_name" --arg db "$db" --arg pfx "$PREFIX_BASE" '
        def to_int: (floor|tostring);

        .MetricDataResults[]
        | select((.Values|length) > 0)
        | .Label as $m
        | (.Values[0]) as $v
        | if ($m == "FreeStorageSpace" or $m == "FreeableMemory") then
            "name=\($pfx)|\($acct)|\($db)|metrics|\($m) (KB), value=\((($v/1024))|to_int)"
          elif ($m == "ReadLatency" or $m == "WriteLatency") then
            "name=\($pfx)|\($acct)|\($db)|metrics|\($m) (ms), value=\((($v*1000))|to_int)"
          else
            "name=\($pfx)|\($acct)|\($db)|metrics|\($m), value=\(($v)|to_int)"
          end
      ' >> "$OUTPUT_FILE"

      start_idx="$end_idx"
    done
  done
done

# Print ALL metrics at once (stdout). Logs stayed on stderr.
sort "$OUTPUT_FILE"
