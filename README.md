# supabase-audit

Supabase の外部公開 API 面（主に PostgREST / Storage）を簡易チェックするシェルスクリプトです。  
`anon` キーや `noauth` でアクセス可否を確認し、公開しすぎの兆候を検出します。

## できること

- テーブル/ビューの read 可否チェック
- OpenAPI からのテーブル/ビュー 自動検出（`--auto-tables`）
- `noauth / anon / user` のアクセス比較（`--auth-matrix`）
- Storage バケット列挙と list 可否チェック（`--storage-probe`）
- 検知結果の JSON 出力（`--report-json`）
- High finding 検知時に CI を fail（`--strict`）
- レート制御（`--sleep-ms`）

## 必要環境

- Bash
- `curl`
- `jq`

## クイックスタート

### 1. テーブル一覧ファイルで実行

```bash
SUPABASE_URL=https://xxx.supabase.co \
SUPABASE_ANON_KEY=xxx \
./sb-audit.sh --tables tables.txt
```

### 2. 自動検出で実行

```bash
SUPABASE_URL=https://xxx.supabase.co \
SUPABASE_ANON_KEY=xxx \
./sb-audit.sh --auto-tables --noauth-probe
```

### 3. 拡張チェック + CI 向け

```bash
SUPABASE_URL=https://xxx.supabase.co \
SUPABASE_ANON_KEY=xxx \
SUPABASE_USER_JWT=xxx \
./sb-audit.sh \
  --auto-tables --auth-matrix --storage-probe --sleep-ms 200 \
  --strict --report-json report.json
```

## 主なオプション

- `--tables <file>`: テーブル名リスト（1行1件）
- `--auto-tables`: `/rest/v1/` OpenAPI から table/view を抽出
- `--noauth-probe`: ヘッダなしアクセスの read チェック
- `--auth-matrix`: `noauth / anon / user` を比較表示
- `--user-jwt <jwt>`: `--auth-matrix` の user 用 JWT
- `--storage-probe`: 各バケットへの object list 試行
- `--sample-read`: 1行サンプルを取得してキー名を表示（本番は非推奨）
- `--sleep-ms <n>`: 各ターゲット間で `n` ミリ秒待機（デフォルト: 200）
- `--strict`: High finding があると `exit 1`
- `--report-json <file>`: レポートを JSON で保存

## findings の扱い

- `high`: 例) `noauth` で table read/list が成功
- `medium`: 例) `anon` で read/list が成功、公開 bucket、敏感そうな名前
- `low`: 現在は未使用（将来拡張用）

`--strict` は `high > 0` のときに失敗終了します。

## 注意点

- これは **外部公開面の挙動診断** です。完全な脆弱性診断ではありません。
- RLS policy の中身精査、DB ロール権限監査、関数実装監査は別途必要です。
- `--auto-tables` は OpenAPI 可視範囲に依存します。
- RPC は副作用のある関数実行リスクを避けるため、このスクリプトでは未チェックです。
- 既定ではテーブル本文を取得しません。`--sample-read` は検証環境でのみ推奨です。

## 補足

- 実行例は [`run.sh`](./run.sh) にも記載しています。
- 詳細オプションは `./sb-audit.sh --help` を参照してください。
