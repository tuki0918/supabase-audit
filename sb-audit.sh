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
sb-audit.sh - Supabase external-view audit (ALLOWLIST tables)

Required:
  --tables <file>        File containing table names (one per line)
  --url <supabase_url>   e.g. https://xxxx.supabase.co   (or env SUPABASE_URL)
  --anon <anon_key>      anon key JWT                    (or env SUPABASE_ANON_KEY)

Optional:
  --sensitive <regex>    Regex for sensitive keys (default: (email|password|phone|token|secret|address|birth|salary|ip))
  --write-probe          Try safe-ish write probe (OFF by default; see notes)
  -h, --help             Show this help

Notes:
- This script does NOT auto-discover tables. Provide an allowlist tables file.
- Write probe is dangerous; keep it off unless you know your schema/policies.
EOF
}

TABLES_FILE=""
ARG_URL=""
ARG_ANON=""
ARG_SENSITIVE=""
WRITE_PROBE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tables) TABLES_FILE="${2:-}"; shift 2 ;;
    --url) ARG_URL="${2:-}"; shift 2 ;;
    --anon) ARG_ANON="${2:-}"; shift 2 ;;
    --sensitive) ARG_SENSITIVE="${2:-}"; shift 2 ;;
    --write-probe) WRITE_PROBE=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

SUPABASE_URL="${ARG_URL:-${SUPABASE_URL:-}}"
SUPABASE_ANON_KEY="${ARG_ANON:-${SUPABASE_ANON_KEY:-}}"
SENSITIVE_REGEX="${ARG_SENSITIVE:-${SENSITIVE_REGEX:-"(email|password|pass|phone|tel|ssn|credit|card|token|secret|address|birth|birthday|salary|ip)"}}"

if [[ -z "${TABLES_FILE}" || ! -f "${TABLES_FILE}" ]]; then
  echo "tables file is required and must exist: --tables <file>" >&2
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

echo "== Supabase external audit (allowlist) =="
echo "URL: ${SUPABASE_URL}"
echo "Tables: ${TABLES_FILE}"
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
done < "${TABLES_FILE}"

echo "Done."
