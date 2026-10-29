#!/usr/bin/env bash
# ローカルで一通りの流れを再現するデモ。
#   1. CA と証明書（ブローカー / モックAPI / エージェント / 管理者）を発行
#   2. モックの OpenAI 互換 API とブローカーを起動
#   3. 管理者が API キーを登録 → エージェントがトークン取得 → 代理呼び出し
#   4. 許可外エンドポイント・トークン盗用・キー漏洩が防がれることを確認
#   5. 監査ログのハッシュチェーンを検証
set -euo pipefail
cd "$(dirname "$0")/.."

WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORK"' EXIT
BIN=$WORK/bin
mkdir -p "$BIN" "$WORK/data"
go build -o "$BIN" ./cmd/... ./examples/mock-upstream

P=$WORK/pki
"$BIN/kagi-ca" init  -dir "$P" >/dev/null
"$BIN/kagi-ca" issue -dir "$P" -kind server -name broker   -hosts localhost,127.0.0.1 >/dev/null
"$BIN/kagi-ca" issue -dir "$P" -kind server -name upstream -hosts localhost,127.0.0.1 >/dev/null
"$BIN/kagi-ca" issue -dir "$P" -kind agent  -name yata >/dev/null
"$BIN/kagi-ca" issue -dir "$P" -kind agent  -name intruder >/dev/null
"$BIN/kagi-ca" issue -dir "$P" -kind admin  -name ops >/dev/null

API_KEY=sk-demo-1234567890abcdef
cat > "$WORK/policy.json" <<EOF
{"upstreams": {"openai": {"base_url": "https://127.0.0.1:9443", "secret": "openai-api-key",
   "inject": {"header": "Authorization", "format": "Bearer {secret}"}}},
 "agents": {"yata": {"grants": [{"upstream": "openai", "max_ttl": "10m", "max_requests": 20,
   "allow": [{"method": "POST", "path": "/v1/chat/completions"},
             {"method": "GET",  "path": "/v1/debug/headers"}]}]}}}
EOF
printf 'demo-passphrase-change-me' > "$WORK/passphrase"

"$BIN/mock-upstream" -cert "$P/upstream.crt" -key "$P/upstream.key" -api-key "$API_KEY" 2>/dev/null &
KAGI_PASSPHRASE_FILE=$WORK/passphrase "$BIN/kagid" \
  -tls-cert "$P/broker.crt" -tls-key "$P/broker.key" -client-ca "$P/ca.crt" \
  -policy "$WORK/policy.json" -vault "$WORK/data/vault.json" -audit "$WORK/data/audit.log" \
  -dev-allow-private-upstreams -dev-upstream-ca "$P/ca.crt" 2>"$WORK/kagid.log" &
for _ in $(seq 50); do curl -sf http://127.0.0.1:9090/healthz >/dev/null && break; sleep 0.1; done

B=https://localhost:8443
as() { local who=$1; shift; curl -s --cacert "$P/ca.crt" --cert "$P/$who.crt" --key "$P/$who.key" "$@"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "管理者が API キーを登録（標準入力から。シェル履歴に残さない）"
printf '%s' "$API_KEY" | KAGI_CERT=$P/ops.crt KAGI_KEY=$P/ops.key KAGI_CA=$P/ca.crt "$BIN/kagictl" secret put openai-api-key

step "エージェント yata が短命トークンを取得"
TOKJSON=$(as yata -X POST $B/v1/token -d '{"upstream":"openai","ttl":"5m","purpose":"demo"}')
echo "$TOKJSON"
TOK=$(echo "$TOKJSON" | sed -E 's/.*"token":"([^"]+)".*/\1/')

step "ブローカー経由で LLM API を呼ぶ（エージェントは本物のキーを知らない）"
as yata -X POST $B/v1/proxy/openai/v1/chat/completions -H "Authorization: Bearer $TOK" \
  -d '{"model":"gpt-demo","messages":[{"role":"user","content":"こんにちは"}]}'

step "上流APIがキーをエコーしても、レスポンスから伏字化される"
as yata $B/v1/proxy/openai/v1/debug/headers -H "Authorization: Bearer $TOK"

step "許可されていないエンドポイント → 403"
as yata -X DELETE $B/v1/proxy/openai/v1/files/abc -H "Authorization: Bearer $TOK" -w ' [%{http_code}]\n'

step "トークンを盗んだ別エージェントが使う → 401（証明書バインド）"
as intruder -X POST $B/v1/proxy/openai/v1/chat/completions -H "Authorization: Bearer $TOK" -w ' [%{http_code}]\n'

step "クライアント証明書なし → TLS ハンドシェイクで拒否"
curl -s --cacert "$P/ca.crt" $B/v1/token -o /dev/null -w '[%{http_code}] ' || echo "接続拒否 (curl exit $?)"

step "メトリクス"
curl -s http://127.0.0.1:9090/metrics

step "監査ログ（キーもトークンも記録されない）"
cat "$WORK/data/audit.log" | cut -c1-200

step "監査ログのハッシュチェーン検証"
KAGI_PASSPHRASE_FILE=$WORK/passphrase "$BIN/kagid" -vault "$WORK/data/vault.json" -audit "$WORK/data/audit.log" -verify-audit

step "監査ログを1文字改ざんすると検知される"
sed -i 's/"result":"forward/"result":"FORWARD/' "$WORK/data/audit.log"
KAGI_PASSPHRASE_FILE=$WORK/passphrase "$BIN/kagid" -vault "$WORK/data/vault.json" -audit "$WORK/data/audit.log" -verify-audit || true

if grep -q "$API_KEY" "$WORK/data/vault.json"; then echo "FAIL: 平文キーがディスク上にある"; exit 1; fi
echo; echo "デモ完了"
