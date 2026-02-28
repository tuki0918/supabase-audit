# supabase-audit

`supabase-audit` is a shell script for checking external exposure on Supabase Data API surfaces (mainly PostgREST and Storage).
It validates access behavior for `anon` and optional `noauth` paths to detect overexposed endpoints.

## What it does

- Checks table/view read accessibility
- Auto-discovers table/view targets from `/rest/v1/` OpenAPI (`--auto-tables`)
- Compares access as `noauth / anon / user` (`--auth-matrix`)
- Probes Storage bucket listing permissions (`--storage-probe`)
- Writes machine-readable JSON reports (`--report-json`)
- Fails CI on high-severity findings (`--strict`)
- Supports probe throttling (`--sleep-ms`, default: `200`)

## Requirements

- Bash
- `curl`
- `jq`

## Quick start

### 1. Manual table list

```bash
SUPABASE_URL=https://xxx.supabase.co \
SUPABASE_ANON_KEY=xxx \
./sb-audit.sh --tables tables.txt
```

### 2. Auto-discovery

```bash
SUPABASE_URL=https://xxx.supabase.co \
SUPABASE_ANON_KEY=xxx \
./sb-audit.sh --auto-tables --noauth-probe
```

### 3. CI-oriented run

```bash
SUPABASE_URL=https://xxx.supabase.co \
SUPABASE_ANON_KEY=xxx \
SUPABASE_USER_JWT=xxx \
./sb-audit.sh \
  --auto-tables --auth-matrix --storage-probe --sleep-ms 200 \
  --strict --report-json report.json
```

## Main options

- `--tables <file>`: table names (one per line)
- `--auto-tables`: discover table/view names from `/rest/v1/` OpenAPI
- `--noauth-probe`: test read access without auth headers
- `--auth-matrix`: compare `noauth / anon / user`
- `--user-jwt <jwt>`: user JWT used by `--auth-matrix`
- `--storage-probe`: test Storage object list access per bucket
- `--sample-read`: fetch one sample row to inspect keys (not recommended for production data)
- `--sleep-ms <n>`: sleep `n` milliseconds between target probes (default: `200`)
- `--strict`: exit with status `1` when high-severity findings exist
- `--report-json <file>`: write summary/findings as JSON
- `--sensitive <regex>`: regex for sensitive-looking field names

## Finding levels

- `high`: examples include successful `noauth` table read/list access
- `medium`: examples include successful `anon` read/list access, public buckets, or sensitive-looking field names
- `low`: reserved for future use

`--strict` currently fails only when `high > 0`.

## Safety and scope

- This is an external exposure behavior check, not a full vulnerability assessment.
- Full security review still requires RLS policy review, DB role/grant review, and function/code review.
- `--auto-tables` depends on OpenAPI visibility and project configuration.
- RPC checks are intentionally not included to avoid accidental execution of side-effect functions.
- By default, table row bodies are not fetched. Use `--sample-read` only in safe environments.

## Notes

- See [`run.sh`](./run.sh) for ready-to-run examples.
- For full option details, run `./sb-audit.sh --help`.
