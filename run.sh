#!/usr/bin/env bash

# Manual list
SUPABASE_URL=https://XXX.supabase.co SUPABASE_ANON_KEY=XXX ./sb-audit.sh --tables tables.txt

# OpenAPI auto-discovery + no-auth probe
# SUPABASE_URL=https://XXX.supabase.co SUPABASE_ANON_KEY=XXX ./sb-audit.sh --auto-tables --noauth-probe
