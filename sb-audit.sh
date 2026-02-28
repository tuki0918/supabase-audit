#!/usr/bin/env bash
set -euo pipefail

# Usage examples:
#   ./sb-audit.sh --url "https://xxxx.supabase.co" --anon "eyJ..." --tables tables.txt
#   ./sb-audit.sh --url "https://xxxx.supabase.co" --anon "eyJ..." --tables tables.txt \
#       --sensitive "(mail|email|password|phone|token|secret)"
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
  --sensitive <regex>    Regex for sensitive keys (default: (email|password|phone|token|secret|address|birth|salary|ip))
  --write-probe          Try safe-ish write probe (OFF by default; see notes)
  -h, --help             Show this help

Notes:
- If --auto-tables is enabled, detected names are merged with --tables when both are provided.
- Write probe is dangerous; keep it off unless you know your schema/policies.
EOF
}

TABLES_FILE=""
ARG_URL=""
ARG_ANON=""
ARG_SENSITIVE=""
AUTO_TABLES=false
NOAUTH_PROBE=false
WRITE_PROBE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tables) TABLES_FILE="${2:-}"; shift 2 ;;
    --url) ARG_URL="${2:-}"; shift 2 ;;
    --anon) ARG_ANON="${2:-}"; shift 2 ;;
    --sensitive) ARG_SENSITIVE="${2:-}"; shift 2 ;;
    --auto-tables) AUTO_TABLES=true; shift ;;
    --noauth-probe) NOAUTH_PROBE=true; shift ;;
    --write-probe) WRITE_PROBE=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

SUPABASE_URL="${ARG_URL:-${SUPABASE_URL:-}}"
SUPABASE_ANON_KEY="${ARG_ANON:-${SUPABASE_ANON_KEY:-}}"
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

command -v curl >/dev/null 2>&1 || { echo "curl required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq required" >&2; exit 1; }

auth_headers=(
  -H "apikey: ${SUPABASE_ANON_KEY}"
  -H "Authorization: Bearer ${SUPABASE_ANON_KEY}"
)

DISCOVERED_TABLES_FILE="$(mktemp)"
DISCOVERED_RPC_FILE="$(mktemp)"
COMBINED_TABLES_FILE=""
ACTIVE_TABLES_FILE="${TABLES_FILE}"

cleanup() {
  rm -f "${DISCOVERED_TABLES_FILE}" "${DISCOVERED_RPC_FILE}"
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

if [[ "${AUTO_TABLES}" == "true" ]]; then
  echo "## OpenAPI discovery"
  if discover_from_openapi; then
    discovered_tables_count="$(wc -l < "${DISCOVERED_TABLES_FILE}" | xargs)"
    discovered_rpc_count="$(wc -l < "${DISCOVERED_RPC_FILE}" | xargs)"
    echo "Discovered tables/views: ${discovered_tables_count}"
    echo "Discovered rpc endpoints: ${discovered_rpc_count}"

    if [[ -n "${TABLES_FILE}" ]]; then
      COMBINED_TABLES_FILE="$(mktemp)"
      awk '
        { sub(/#.*/, "", $0); gsub(/^[ \t]+|[ \t]+$/, "", $0); if ($0 != "") print $0 }
      ' "${TABLES_FILE}" "${DISCOVERED_TABLES_FILE}" \
        | sort -u > "${COMBINED_TABLES_FILE}"
      ACTIVE_TABLES_FILE="${COMBINED_TABLES_FILE}"
      echo "Merged table targets: file + OpenAPI"
    else
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
      fi
    fi
  else
    echo "Could not read OpenAPI from /rest/v1/ (auth blocked or not exposed)."
    if [[ -z "${TABLES_FILE}" ]]; then
      echo "Auto discovery failed and no --tables file was provided." >&2
      exit 1
    fi
    echo "Falling back to --tables only."
  fi
  echo
fi

echo "== Supabase external audit =="
echo "URL: ${SUPABASE_URL}"
echo "Tables file input: ${TABLES_FILE:-<none>}"
echo "Tables target source: ${ACTIVE_TABLES_FILE}"
echo "Auto tables: ${AUTO_TABLES}"
echo "No-auth probe: ${NOAUTH_PROBE}"
echo "Sensitive regex: ${SENSITIVE_REGEX}"
echo "Write probe: ${WRITE_PROBE}"
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
if curl -fsS "${auth_headers[@]}" "${SUPABASE_URL}/storage/v1/bucket" | jq . >/dev/null 2>&1; then
  curl -fsS "${auth_headers[@]}" "${SUPABASE_URL}/storage/v1/bucket" \
    | jq 'map({id,name,public,created_at})'
else
  echo "Could not list buckets (may be blocked)."
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

  if [[ "${NOAUTH_PROBE}" == "true" ]]; then
    noauth_code="$(
      curl -sS -o /dev/null -w "%{http_code}" \
        -H "Range: 0-0" \
        -H "Prefer: count=exact" \
        "${SUPABASE_URL}/rest/v1/${table}?select=*&limit=1" || true
    )"
    echo "  NOAUTH READ status: ${noauth_code}"
    if [[ "${noauth_code}" == "200" ]]; then
      echo "  ⚠ NOAUTHで読み取り可能です (apikey/Authorization なし)"
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

  cr="$(grep -i '^content-range:' "${resp_headers}" | tail -n 1 | sed 's/\r$//')"
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

  # Optional write probe: SAFE-ish mode only (Prefer: return=minimal + {}), still risky.
  if [[ "${WRITE_PROBE}" == "true" ]]; then
    echo "  WRITE probe (dangerous): attempting POST {} with return=minimal"
    resp_headers2="$(mktemp)"
    resp_body2="$(mktemp)"
    wcode="$(
      curl -sS -D "${resp_headers2}" -o "${resp_body2}" -w "%{http_code}" \
        "${auth_headers[@]}" \
        -H "Content-Type: application/json" \
        -H "Prefer: return=minimal" \
        -X POST \
        --data '{}' \
        "${SUPABASE_URL}/rest/v1/${table}" || true
    )"
    echo "    WRITE status: ${wcode}"
    werr="$(cat "${resp_body2}" | head -c 400 | tr '\n' ' ' || true)"
    [[ -n "$werr" ]] && echo "    RESP: ${werr}"
    rm -f "${resp_headers2}" "${resp_body2}"
  fi

  echo
done < "${ACTIVE_TABLES_FILE}"

echo "Done."
