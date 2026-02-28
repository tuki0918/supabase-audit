#!/usr/bin/env bash
set -euo pipefail

# Usage examples:
#   ./sb-audit.sh --url "https://xxxx.supabase.co" --anon "eyJ..." --tables tables.txt
#   ./sb-audit.sh --url "https://xxxx.supabase.co" --anon "eyJ..." --tables tables.txt \
#       --sensitive "(mail|email|password|phone|token|secret)"
#   ./sb-audit.sh --url "https://xxxx.supabase.co" --anon "eyJ..." --auto-tables \
#       --auth-matrix --rpc-probe --storage-probe \
#       --strict --report-json report.json
#
# Env vars also supported (args override env):
#   SUPABASE_URL=... SUPABASE_ANON_KEY=... SENSITIVE_REGEX=... ./sb-audit.sh --tables tables.txt

usage() {
  cat <<'EOF'
sb-audit.sh - Supabase external-view audit

Required:
  --tables <file>        File containing table names (one per line)
                         (or use --auto-tables)
  --url <supabase_url>   e.g. https://xxxx.supabase.co   (or env SUPABASE_URL)
  --anon <anon_key>      anon key JWT                    (or env SUPABASE_ANON_KEY)

Optional:
  --auto-tables          Discover table/view names from /rest/v1/ OpenAPI
  --noauth-probe         Probe read endpoints without apikey/auth headers
  --auth-matrix          Compare access with noauth / anon / user JWT
  --user-jwt <jwt>       User JWT for --auth-matrix (or env SUPABASE_USER_JWT)
  --rpc-probe            Probe discovered RPC endpoints with POST {}
  --storage-probe        Probe storage object/list access per bucket
  --strict               Exit 1 when high-severity findings are detected
  --report-json <file>   Write summary + findings JSON report
  --sensitive <regex>    Regex for sensitive keys (default: (email|password|phone|token|secret|address|birth|salary|ip))
  -h, --help             Show this help

Notes:
- If --auto-tables is enabled, detected names are merged with --tables when both are provided.
EOF
}

TABLES_FILE=""
ARG_URL=""
ARG_ANON=""
ARG_USER_JWT=""
ARG_SENSITIVE=""
AUTO_TABLES=false
NOAUTH_PROBE=false
AUTH_MATRIX=false
RPC_PROBE=false
STORAGE_PROBE=false
STRICT_MODE=false
REPORT_JSON_FILE=""
REPORT_JSON_ENABLED=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tables) TABLES_FILE="${2:-}"; shift 2 ;;
    --url) ARG_URL="${2:-}"; shift 2 ;;
    --anon) ARG_ANON="${2:-}"; shift 2 ;;
    --user-jwt) ARG_USER_JWT="${2:-}"; shift 2 ;;
    --sensitive) ARG_SENSITIVE="${2:-}"; shift 2 ;;
    --auto-tables) AUTO_TABLES=true; shift ;;
    --noauth-probe) NOAUTH_PROBE=true; shift ;;
    --auth-matrix) AUTH_MATRIX=true; shift ;;
    --rpc-probe) RPC_PROBE=true; shift ;;
    --storage-probe) STORAGE_PROBE=true; shift ;;
    --strict) STRICT_MODE=true; shift ;;
    --report-json) REPORT_JSON_ENABLED=true; REPORT_JSON_FILE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

SUPABASE_URL="${ARG_URL:-${SUPABASE_URL:-}}"
SUPABASE_ANON_KEY="${ARG_ANON:-${SUPABASE_ANON_KEY:-}}"
SUPABASE_USER_JWT="${ARG_USER_JWT:-${SUPABASE_USER_JWT:-}}"
SENSITIVE_REGEX="${ARG_SENSITIVE:-${SENSITIVE_REGEX:-"(email|password|pass|phone|tel|ssn|credit|card|token|secret|address|birth|birthday|salary|ip)"}}"

if [[ -n "${TABLES_FILE}" && ! -f "${TABLES_FILE}" ]]; then
  echo "tables file must exist: --tables <file>" >&2
  exit 1
fi
if [[ -z "${TABLES_FILE}" && "${AUTO_TABLES}" != "true" ]]; then
  echo "Either --tables <file> or --auto-tables is required." >&2
  exit 1
fi
if [[ -z "${SUPABASE_URL}" ]]; then
  echo "SUPABASE_URL is required (--url or env SUPABASE_URL)" >&2
  exit 1
fi
if [[ -z "${SUPABASE_ANON_KEY}" ]]; then
  echo "SUPABASE_ANON_KEY is required (--anon or env SUPABASE_ANON_KEY)" >&2
  exit 1
fi
if [[ "${REPORT_JSON_ENABLED}" == "true" && -z "${REPORT_JSON_FILE}" ]]; then
  echo "--report-json requires a file path argument" >&2
  exit 1
fi
if [[ -n "${REPORT_JSON_FILE}" && "${REPORT_JSON_FILE}" == "--"* ]]; then
  echo "--report-json requires a file path argument" >&2
  exit 1
fi
RUN_AT_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

command -v curl >/dev/null 2>&1 || { echo "curl required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq required" >&2; exit 1; }

auth_headers=(
  -H "apikey: ${SUPABASE_ANON_KEY}"
  -H "Authorization: Bearer ${SUPABASE_ANON_KEY}"
)

user_headers=()
if [[ -n "${SUPABASE_USER_JWT}" ]]; then
  user_headers=(
    -H "apikey: ${SUPABASE_ANON_KEY}"
    -H "Authorization: Bearer ${SUPABASE_USER_JWT}"
  )
fi

mode_read_status() {
  local mode="$1"
  local table="$2"
  local -a headers=()
  case "${mode}" in
    noauth) ;;
    anon) headers=("${auth_headers[@]}") ;;
    user)
      if [[ -z "${SUPABASE_USER_JWT}" ]]; then
        echo "N/A"
        return 0
      fi
      headers=("${user_headers[@]}")
      ;;
    *) echo "N/A"; return 0 ;;
  esac

  curl -sS -o /dev/null -w "%{http_code}" \
    "${headers[@]}" \
    -H "Range: 0-0" \
    -H "Prefer: count=exact" \
    "${SUPABASE_URL}/rest/v1/${table}?select=*&limit=1" || true
}

mode_rpc_status() {
  local mode="$1"
  local rpc="$2"
  local -a headers=()
  case "${mode}" in
    noauth) ;;
    anon) headers=("${auth_headers[@]}") ;;
    user)
      if [[ -z "${SUPABASE_USER_JWT}" ]]; then
        echo "N/A"
        return 0
      fi
      headers=("${user_headers[@]}")
      ;;
    *) echo "N/A"; return 0 ;;
  esac

  curl -sS -o /dev/null -w "%{http_code}" \
    "${headers[@]}" \
    -H "Content-Type: application/json" \
    -X POST \
    --data '{}' \
    "${SUPABASE_URL}/rest/v1/rpc/${rpc}" || true
}

mode_storage_list_status() {
  local mode="$1"
  local bucket="$2"
  local -a headers=()
  case "${mode}" in
    noauth) ;;
    anon) headers=("${auth_headers[@]}") ;;
    user)
      if [[ -z "${SUPABASE_USER_JWT}" ]]; then
        echo "N/A"
        return 0
      fi
      headers=("${user_headers[@]}")
      ;;
    *) echo "N/A"; return 0 ;;
  esac

  curl -sS -o /dev/null -w "%{http_code}" \
    "${headers[@]}" \
    -H "Content-Type: application/json" \
    -X POST \
    --data '{"limit":1,"offset":0}' \
    "${SUPABASE_URL}/storage/v1/object/list/${bucket}" || true
}

DISCOVERED_TABLES_FILE="$(mktemp)"
DISCOVERED_RPC_FILE="$(mktemp)"
DISCOVERED_BUCKETS_FILE="$(mktemp)"
FINDINGS_FILE="$(mktemp)"
COMBINED_TABLES_FILE=""
ACTIVE_TABLES_FILE="${TABLES_FILE}"

add_finding() {
  local severity="$1"
  local category="$2"
  local target="$3"
  local message="$4"
  jq -nc \
    --arg severity "${severity}" \
    --arg category "${category}" \
    --arg target "${target}" \
    --arg message "${message}" \
    '{severity:$severity,category:$category,target:$target,message:$message}' >> "${FINDINGS_FILE}"
}

is_success_code() {
  local code="$1"
  [[ "${code}" =~ ^2[0-9][0-9]$ ]]
}

cleanup() {
  rm -f "${DISCOVERED_TABLES_FILE}" "${DISCOVERED_RPC_FILE}" "${DISCOVERED_BUCKETS_FILE}" "${FINDINGS_FILE}"
  if [[ -n "${COMBINED_TABLES_FILE}" ]]; then
    rm -f "${COMBINED_TABLES_FILE}"
  fi
}
trap cleanup EXIT

discover_from_openapi() {
  local openapi_headers openapi_body openapi_code
  openapi_headers="$(mktemp)"
  openapi_body="$(mktemp)"

  openapi_code="$(
    curl -sS -D "${openapi_headers}" -o "${openapi_body}" -w "%{http_code}" \
      "${auth_headers[@]}" \
      -H "Accept: application/openapi+json" \
      "${SUPABASE_URL}/rest/v1/" || true
  )"

  if [[ "${openapi_code}" != "200" ]] || ! jq -e '.paths' "${openapi_body}" >/dev/null 2>&1; then
    rm -f "${openapi_headers}" "${openapi_body}"
    return 1
  fi

  jq -r '.paths | keys[]' "${openapi_body}" \
    | sed -n 's#^/##p' \
    | awk -F'/' 'NF==1 && $1 != "rpc" && $1 != "" { print $1 }' \
    | sort -u > "${DISCOVERED_TABLES_FILE}"

  jq -r '.paths | keys[]' "${openapi_body}" \
    | sed -n 's#^/rpc/##p' \
    | awk -F'/' 'NF==1 && $1 != "" { print $1 }' \
    | sort -u > "${DISCOVERED_RPC_FILE}"

  rm -f "${openapi_headers}" "${openapi_body}"
  return 0
}

if [[ "${AUTO_TABLES}" == "true" || "${RPC_PROBE}" == "true" ]]; then
  echo "## OpenAPI discovery"
  if discover_from_openapi; then
    discovered_tables_count="$(wc -l < "${DISCOVERED_TABLES_FILE}" | xargs)"
    discovered_rpc_count="$(wc -l < "${DISCOVERED_RPC_FILE}" | xargs)"
    echo "Discovered tables/views: ${discovered_tables_count}"
    echo "Discovered rpc endpoints: ${discovered_rpc_count}"

    if [[ "${AUTO_TABLES}" == "true" && -n "${TABLES_FILE}" ]]; then
      COMBINED_TABLES_FILE="$(mktemp)"
      awk '
        { sub(/#.*/, "", $0); gsub(/^[ \t]+|[ \t]+$/, "", $0); if ($0 != "") print $0 }
      ' "${TABLES_FILE}" "${DISCOVERED_TABLES_FILE}" \
        | sort -u > "${COMBINED_TABLES_FILE}"
      ACTIVE_TABLES_FILE="${COMBINED_TABLES_FILE}"
      echo "Merged table targets: file + OpenAPI"
    elif [[ "${AUTO_TABLES}" == "true" ]]; then
      ACTIVE_TABLES_FILE="${DISCOVERED_TABLES_FILE}"
      echo "Using OpenAPI-discovered table targets"
    fi

    if [[ -s "${DISCOVERED_RPC_FILE}" ]]; then
      echo "RPC list:"
      sed 's/^/  - /' "${DISCOVERED_RPC_FILE}"
      sensitive_rpc="$(grep -Ei "${SENSITIVE_REGEX}" "${DISCOVERED_RPC_FILE}" || true)"
      if [[ -n "${sensitive_rpc}" ]]; then
        echo "  ⚠ Sensitive-like rpc names found:"
        echo "${sensitive_rpc}" | sed 's/^/    - /'
        while IFS= read -r rpc_name; do
          [[ -z "${rpc_name}" ]] && continue
          add_finding "medium" "rpc_name" "${rpc_name}" "RPC name matches sensitive pattern"
        done <<< "${sensitive_rpc}"
      fi
    fi
  else
    echo "Could not read OpenAPI from /rest/v1/ (auth blocked or not exposed)."
    if [[ "${RPC_PROBE}" == "true" ]]; then
      add_finding "medium" "openapi" "/rest/v1/" "OpenAPI discovery failed; RPC probe coverage is incomplete"
    fi
    if [[ "${AUTO_TABLES}" == "true" && -z "${TABLES_FILE}" ]]; then
      echo "Auto discovery failed and no --tables file was provided." >&2
      exit 1
    fi
    if [[ "${AUTO_TABLES}" == "true" ]]; then
      echo "Falling back to --tables only."
    fi
  fi
  echo
fi

echo "== Supabase external audit =="
echo "URL: ${SUPABASE_URL}"
echo "Tables file input: ${TABLES_FILE:-<none>}"
echo "Tables target source: ${ACTIVE_TABLES_FILE}"
echo "Auto tables: ${AUTO_TABLES}"
echo "No-auth probe: ${NOAUTH_PROBE}"
echo "Auth matrix: ${AUTH_MATRIX}"
echo "User JWT provided: $( [[ -n "${SUPABASE_USER_JWT}" ]] && echo yes || echo no )"
echo "RPC probe: ${RPC_PROBE}"
echo "Storage probe: ${STORAGE_PROBE}"
echo "Strict mode: ${STRICT_MODE}"
echo "Report JSON: ${REPORT_JSON_FILE:-<none>}"
echo "Sensitive regex: ${SENSITIVE_REGEX}"
if [[ "${AUTH_MATRIX}" == "true" && -z "${SUPABASE_USER_JWT}" ]]; then
  echo "Note: --auth-matrix enabled without --user-jwt (user= N/A)."
fi
echo

# Auth settings (best-effort)
echo "## Auth settings"
if curl -fsS "${auth_headers[@]}" "${SUPABASE_URL}/auth/v1/settings" | jq . >/dev/null 2>&1; then
  curl -fsS "${auth_headers[@]}" "${SUPABASE_URL}/auth/v1/settings" \
    | jq '{anonymous_login_enabled, disable_signup, mailer_autoconfirm}' 2>/dev/null || true
else
  echo "Could not read /auth/v1/settings (may be blocked)."
fi
echo

# Storage buckets (best-effort)
echo "## Storage buckets"
bucket_headers="$(mktemp)"
bucket_body="$(mktemp)"
bucket_http="$(
  curl -sS -D "${bucket_headers}" -o "${bucket_body}" -w "%{http_code}" \
    "${auth_headers[@]}" \
    "${SUPABASE_URL}/storage/v1/bucket" || true
)"

if [[ "${bucket_http}" == "200" ]] && jq -e . "${bucket_body}" >/dev/null 2>&1; then
  cat "${bucket_body}" | jq 'map({id,name,public,created_at})'
  cat "${bucket_body}" | jq -r '.[]?.id // empty' | sort -u > "${DISCOVERED_BUCKETS_FILE}"
  public_buckets="$(cat "${bucket_body}" | jq -r '.[]? | select(.public==true) | .id' || true)"
  if [[ -n "${public_buckets}" ]]; then
    echo "⚠ Public buckets:"
    echo "${public_buckets}" | sed 's/^/  - /'
    while IFS= read -r bucket_name; do
      [[ -z "${bucket_name}" ]] && continue
      add_finding "medium" "storage_bucket" "${bucket_name}" "Bucket is public=true"
    done <<< "${public_buckets}"
  fi
else
  echo "Could not list buckets (may be blocked)."
fi
rm -f "${bucket_headers}" "${bucket_body}"
echo

if [[ "${STORAGE_PROBE}" == "true" ]]; then
  echo "## Storage object/list probe"
  if [[ -s "${DISCOVERED_BUCKETS_FILE}" ]]; then
    while IFS= read -r bucket; do
      [[ -z "${bucket}" ]] && continue
      echo "-- ${bucket}"
      if [[ "${AUTH_MATRIX}" == "true" ]]; then
        s_noauth="$(mode_storage_list_status "noauth" "${bucket}")"
        s_anon="$(mode_storage_list_status "anon" "${bucket}")"
        s_user="$(mode_storage_list_status "user" "${bucket}")"
        echo "  LIST status matrix: noauth=${s_noauth} anon=${s_anon} user=${s_user}"
        if is_success_code "${s_noauth}"; then
          add_finding "high" "storage_list" "${bucket}" "Storage list endpoint is accessible without auth"
        fi
        if is_success_code "${s_anon}"; then
          add_finding "medium" "storage_list" "${bucket}" "Storage list endpoint is accessible with anon key"
        fi
      else
        s_anon="$(mode_storage_list_status "anon" "${bucket}")"
        echo "  LIST status (anon): ${s_anon}"
        if is_success_code "${s_anon}"; then
          add_finding "medium" "storage_list" "${bucket}" "Storage list endpoint is accessible with anon key"
        fi
        if [[ "${NOAUTH_PROBE}" == "true" ]]; then
          s_noauth="$(mode_storage_list_status "noauth" "${bucket}")"
          echo "  LIST status (noauth): ${s_noauth}"
          if is_success_code "${s_noauth}"; then
            add_finding "high" "storage_list" "${bucket}" "Storage list endpoint is accessible without auth"
          fi
        fi
      fi
    done < "${DISCOVERED_BUCKETS_FILE}"
  else
    echo "No buckets discovered; skip storage probe."
  fi
fi
echo

echo "## Table checks"

mask_sensitive_json() {
  # Masks values for keys matching SENSITIVE_REGEX in a JSON object (single row)
  jq --arg re "${SENSITIVE_REGEX}" '
    if type=="object" then
      with_entries(if (.key|test($re;"i")) then .value="***" else . end)
    else
      .
    end
  '
}

extract_keys() {
  jq -r '
    if type=="array" and length>0 and .[0]|type=="object" then .[0]|keys[] 
    elif type=="object" then keys[]
    else empty end
  '
}

while IFS= read -r table; do
  table="$(echo "$table" | sed 's/#.*$//' | xargs || true)"
  [[ -z "$table" ]] && continue

  echo "-- ${table}"

  if [[ "${AUTH_MATRIX}" == "true" ]]; then
    read_noauth="$(mode_read_status "noauth" "${table}")"
    read_anon="$(mode_read_status "anon" "${table}")"
    read_user="$(mode_read_status "user" "${table}")"
    echo "  READ status matrix: noauth=${read_noauth} anon=${read_anon} user=${read_user}"
    if [[ "${read_noauth}" == "200" ]]; then
      echo "  ⚠ NOAUTHで読み取り可能です (apikey/Authorization なし)"
      add_finding "high" "table_read" "${table}" "Table read is accessible without auth"
    fi
    if [[ "${read_anon}" == "200" ]]; then
      add_finding "medium" "table_read" "${table}" "Table read is accessible with anon key"
    fi
  elif [[ "${NOAUTH_PROBE}" == "true" ]]; then
    read_noauth="$(mode_read_status "noauth" "${table}")"
    echo "  NOAUTH READ status: ${read_noauth}"
    if [[ "${read_noauth}" == "200" ]]; then
      echo "  ⚠ NOAUTHで読み取り可能です (apikey/Authorization なし)"
      add_finding "high" "table_read" "${table}" "Table read is accessible without auth"
    fi
  fi

  resp_headers="$(mktemp)"
  resp_body="$(mktemp)"

  http_code="$(
    curl -sS -D "${resp_headers}" -o "${resp_body}" -w "%{http_code}" \
      "${auth_headers[@]}" \
      -H "Range: 0-0" \
      -H "Prefer: count=exact" \
      "${SUPABASE_URL}/rest/v1/${table}?select=*&limit=1" || true
  )"

  echo "  READ status: ${http_code}"

  cr="$(grep -i '^content-range:' "${resp_headers}" | tail -n 1 | sed 's/\r$//' || true)"
  [[ -n "$cr" ]] && echo "  ${cr}"

  if [[ "${http_code}" == "200" ]]; then
    if jq -e . "${resp_body}" >/dev/null 2>&1; then
      keys="$(cat "${resp_body}" | extract_keys | tr '\n' ' ' || true)"
      [[ -n "$keys" ]] && echo "  Keys(sample): ${keys}"

      # detect sensitive keys
      sensitive_keys="$(cat "${resp_body}" | extract_keys | grep -Ei "${SENSITIVE_REGEX}" || true)"
      if [[ -n "$sensitive_keys" ]]; then
        echo "  ⚠ Sensitive-like keys found:"
        echo "$sensitive_keys" | sed 's/^/    - /'
        while IFS= read -r key_name; do
          [[ -z "${key_name}" ]] && continue
          add_finding "medium" "column_name" "${table}.${key_name}" "Column name matches sensitive pattern"
        done <<< "${sensitive_keys}"
      fi

      # show masked sample
      sample="$(jq '.[0] // .' "${resp_body}" | mask_sensitive_json 2>/dev/null || true)"
      if [[ -n "$sample" ]]; then
        echo "  Sample(masked):"
        echo "$sample" | sed 's/^/    /'
      fi
    else
      echo "  Body is not JSON."
    fi
  elif [[ "${http_code}" == "401" || "${http_code}" == "403" ]]; then
    echo "  READ blocked (good if intended)"
  else
    err="$(cat "${resp_body}" | head -c 400 | tr '\n' ' ' || true)"
    [[ -n "$err" ]] && echo "  RESP: ${err}"
  fi

  rm -f "${resp_headers}" "${resp_body}"

  echo
done < "${ACTIVE_TABLES_FILE}"

if [[ "${RPC_PROBE}" == "true" ]]; then
  echo "## RPC probes"
  if [[ -s "${DISCOVERED_RPC_FILE}" ]]; then
    while IFS= read -r rpc; do
      [[ -z "${rpc}" ]] && continue
      echo "-- ${rpc}"
      if [[ "${AUTH_MATRIX}" == "true" ]]; then
        r_noauth="$(mode_rpc_status "noauth" "${rpc}")"
        r_anon="$(mode_rpc_status "anon" "${rpc}")"
        r_user="$(mode_rpc_status "user" "${rpc}")"
        echo "  RPC status matrix: noauth=${r_noauth} anon=${r_anon} user=${r_user}"
        if is_success_code "${r_noauth}"; then
          add_finding "high" "rpc_exec" "${rpc}" "RPC appears callable without auth"
        fi
        if is_success_code "${r_anon}"; then
          add_finding "medium" "rpc_exec" "${rpc}" "RPC appears callable with anon key"
        fi
      else
        r_anon="$(mode_rpc_status "anon" "${rpc}")"
        echo "  RPC status (anon): ${r_anon}"
        if is_success_code "${r_anon}"; then
          add_finding "medium" "rpc_exec" "${rpc}" "RPC appears callable with anon key"
        fi
        if [[ "${NOAUTH_PROBE}" == "true" ]]; then
          r_noauth="$(mode_rpc_status "noauth" "${rpc}")"
          echo "  RPC status (noauth): ${r_noauth}"
          if is_success_code "${r_noauth}"; then
            add_finding "high" "rpc_exec" "${rpc}" "RPC appears callable without auth"
          fi
        fi
      fi
    done < "${DISCOVERED_RPC_FILE}"
  else
    echo "No RPC discovered; skip RPC probe."
  fi
  echo
fi

total_findings="$(wc -l < "${FINDINGS_FILE}" | xargs)"
high_findings="$(jq -s '[.[] | select(.severity=="high")] | length' "${FINDINGS_FILE}")"
medium_findings="$(jq -s '[.[] | select(.severity=="medium")] | length' "${FINDINGS_FILE}")"
low_findings="$(jq -s '[.[] | select(.severity=="low")] | length' "${FINDINGS_FILE}")"

echo "## Findings summary"
echo "Total: ${total_findings}"
echo "High: ${high_findings}"
echo "Medium: ${medium_findings}"
echo "Low: ${low_findings}"

if [[ "${REPORT_JSON_ENABLED}" == "true" ]]; then
  findings_json="$(jq -s '.' "${FINDINGS_FILE}")"
  jq -n \
    --arg generated_at_utc "${RUN_AT_UTC}" \
    --arg url "${SUPABASE_URL}" \
    --arg tables_file "${TABLES_FILE}" \
    --arg tables_target "${ACTIVE_TABLES_FILE}" \
    --arg auto_tables "${AUTO_TABLES}" \
    --arg noauth_probe "${NOAUTH_PROBE}" \
    --arg auth_matrix "${AUTH_MATRIX}" \
    --arg rpc_probe "${RPC_PROBE}" \
    --arg storage_probe "${STORAGE_PROBE}" \
    --arg strict_mode "${STRICT_MODE}" \
    --arg user_jwt_provided "$( [[ -n "${SUPABASE_USER_JWT}" ]] && echo yes || echo no )" \
    --argjson total "${total_findings}" \
    --argjson high "${high_findings}" \
    --argjson medium "${medium_findings}" \
    --argjson low "${low_findings}" \
    --argjson findings "${findings_json}" \
    '{
      generated_at_utc: $generated_at_utc,
      supabase_url: $url,
      options: {
        tables_file: $tables_file,
        tables_target: $tables_target,
        auto_tables: $auto_tables,
        noauth_probe: $noauth_probe,
        auth_matrix: $auth_matrix,
        rpc_probe: $rpc_probe,
        storage_probe: $storage_probe,
        strict_mode: $strict_mode,
        user_jwt_provided: $user_jwt_provided
      },
      summary: {
        total: $total,
        high: $high,
        medium: $medium,
        low: $low
      },
      findings: $findings
    }' > "${REPORT_JSON_FILE}"
  echo "JSON report written: ${REPORT_JSON_FILE}"
fi

if [[ "${STRICT_MODE}" == "true" && "${high_findings}" -gt 0 ]]; then
  echo "Strict mode: high findings detected (${high_findings})" >&2
  exit 1
fi

echo "Done."
