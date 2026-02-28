#!/usr/bin/env bash

set -euo pipefail

# Common env (override with shell env before running this script)
SUPABASE_URL="${SUPABASE_URL:-https://xxx.supabase.co}"
SUPABASE_ANON_KEY="${SUPABASE_ANON_KEY:-xxx}"
SUPABASE_USER_JWT="${SUPABASE_USER_JWT:-}"

run() {
  SUPABASE_URL="${SUPABASE_URL}" \
  SUPABASE_ANON_KEY="${SUPABASE_ANON_KEY}" \
  SUPABASE_USER_JWT="${SUPABASE_USER_JWT}" \
  ./sb-audit.sh "$@"
}

# Manual list
run --tables tables.txt

# OpenAPI auto-discovery + no-auth probe
# run --auto-tables --noauth-probe

# Extended audit (auth matrix + storage)
# run --auto-tables --auth-matrix --storage-probe --sleep-ms 200

# CI-friendly (fail on high findings + JSON output)
# run --auto-tables --auth-matrix --storage-probe --sleep-ms 200 \
#   --strict --report-json report.json

# OpenAPI reachability check
# curl -i \
#   -H "apikey: $SUPABASE_ANON_KEY" \
#   -H "Authorization: Bearer $SUPABASE_ANON_KEY" \
#   -H "Accept: application/openapi+json" \
#   "$SUPABASE_URL/rest/v1/"
