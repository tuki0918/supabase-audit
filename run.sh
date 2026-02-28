#!/usr/bin/env bash

# Manual list
SUPABASE_URL=https://XXX.supabase.co SUPABASE_ANON_KEY=XXX ./sb-audit.sh --tables tables.txt

# OpenAPI auto-discovery + no-auth probe
# SUPABASE_URL=https://XXX.supabase.co SUPABASE_ANON_KEY=XXX ./sb-audit.sh --auto-tables --noauth-probe

# Extended audit (auth matrix + storage)
# SUPABASE_URL=https://XXX.supabase.co SUPABASE_ANON_KEY=XXX SUPABASE_USER_JWT=XXX \
#   ./sb-audit.sh --auto-tables --auth-matrix --storage-probe --sleep-ms 200

# CI-friendly (fail on high findings + JSON output)
# SUPABASE_URL=https://XXX.supabase.co SUPABASE_ANON_KEY=XXX SUPABASE_USER_JWT=XXX \
#   ./sb-audit.sh --auto-tables --auth-matrix --storage-probe --sleep-ms 200 \
#   --strict --report-json report.json
