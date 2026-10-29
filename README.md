# kagi（鍵）— AIエージェントのためのシークレット・ブローカー

> **AIエージェントに、本物のAPIキーを持たせない。**

LLMエージェントに長期のAPIキーを環境変数で渡すと、プロンプトインジェクションひとつでキーが外部に送られたり、意図しないAPIを叩かれたりします。kagi はエージェントとAPIの間に立つブローカーです。エージェントは **mTLS証明書** と **数分で失効するトークン** だけを持ちます。本物のキーはブローカーが通信時に注入します。

```
 ┌──────────────┐  mTLS (TLS 1.3 + X25519MLKEM768)   ┌──────────────┐   HTTPS + 本物のキー   ┌───────────┐
 │  AI Agent    │ ─────────────────────────────────▶ │    kagid     │ ────────────────────▶ │ OpenAI 等 │
 │ (証明書+短命  │  Authorization: Bearer kagi_v1...  │ ・トークン検証 │                       │  上流 API  │
 │  トークンのみ)│ ◀──────────────── 伏字化済みレスポンス │ ・許可リスト   │ ◀──────────────────── │           │
 └──────────────┘                                    │ ・回数上限    │                       └───────────┘
                                                     │ ・SSRF防止    │
                                                     │ ・監査ログ    │──▶ ハッシュチェーン監査ログ
                                                     └──────┬───────┘
                                                            │ エンベロープ暗号化
                                                     ┌──────▼───────┐
                                                     │ vault.json   │  PBKDF2 → KEK → DEK(秘密ごと)
                                                     └──────────────┘
```

依存ライブラリはゼロ（Go 標準ライブラリのみ）。サプライチェーン攻撃面を最小にしています。

---

## なぜ作ったか — 最近のセキュリティ課題との対応

| 課題 | 具体例 | kagi の対策 |
|---|---|---|
| **プロンプトインジェクションによる秘密情報の流出**<br>（OWASP Top 10 for LLM 2025: LLM01 / LLM02） | 悪意あるWebページやメールを読んだエージェントが、キーを攻撃者のURLに送ってしまう | エージェントはキーを**そもそも知らない**。上流がキーをエコーしても、ブローカーがレスポンスから伏字化する |
| **過剰な権限（Excessive Agency, LLM06）** | チャット用のキーでファイル削除や課金APIも叩ける | メソッド＋パス単位の**許可リスト**（デフォルト拒否） |
| **無制限な消費（LLM10）** | 暴走ループでAPI料金が膨らむ | トークンごとの**リクエスト回数上限**、エージェントごとの**レート制限** |
| **トークン盗難** | ログやツール出力経由でトークンが漏れる | トークンを**クライアント証明書に紐付け**（RFC 8705 の考え方）。別の端末では使えない |
| **SSRF / DNSリバインディング** | 内部ネットワークやクラウドのメタデータ（169.254.169.254）へのアクセス | 名前解決**後**の実IPで、プライベート・ループバック・リンクローカル宛を遮断 |
| **"Harvest now, decrypt later"**（耐量子暗号への移行） | 今の暗号通信を保存しておき、将来の量子計算機で解読する | TLS 1.3 で **X25519MLKEM768**（ML-KEM / FIPS 203 のハイブリッド）を優先。`-pq-only` で強制 |
| **CI/CDサプライチェーン攻撃** | 2025年の tj-actions/changed-files 改ざん事件 | GitHub Actions を**コミットSHAでピン留め**し、`permissions: contents: read` で最小権限化。外部依存ゼロ |
| **監査証跡の改ざん** | 侵入者がアクセスログを消して痕跡を隠す | HMAC **ハッシュチェーン**監査ログ。1文字の改ざんも検知 |

## 主な機能

- **mTLS 認証**：SPIFFE 形式のID（`spiffe://kagi.local/agent/yata`）。エージェントと管理者のロールを分離
- **短命・スコープ限定トークン**：Ed25519 署名。最大TTL はポリシーで指定（上限1時間）
- **キー注入プロキシ**：SSE ストリーミング対応で、OpenAI SDK の `base_url` を差し替えるだけで使える
- **レスポンス伏字化**：チャンク境界をまたぐ一致も検出。圧縮でのすり抜けを防ぐため `Accept-Encoding: identity` を強制
- **保存時暗号化**：PBKDF2-SHA256（60万回）→ HKDF → KEK、秘密ごとに DEK を用意（AES-256-GCM）。名前を AAD に含め、暗号文の入れ替えを検知
- **パスフレーズ変更（Rekey）**：DEK を包み直すだけで、秘密の暗号文は変わらない（エンベロープ暗号化の利点）
- **失効**：トークン単位の即時失効、ポリシーのホットリロード（SIGHUP）でグラントごと無効化
- **フェイルクローズ**：監査ログに書けなければリクエストを実行しない
- **運用**：Prometheus 形式のメトリクス、`/healthz`、構造化ログ（JSON）、グレースフルシャットダウン

## クイックスタート（ローカル）

```bash
./scripts/demo.sh   # CA発行 → ブローカーとモックAPIを起動 → 攻撃シナリオを一通り実行
```

出力例（抜粋）：

```
== 上流APIがキーをエコーしても、レスポンスから伏字化される
{"authorization":"Bearer ************************"}
== トークンを盗んだ別エージェントが使う → 401（証明書バインド）
{"error":"token not bound to this client certificate"}
== 監査ログを1文字改ざんすると検知される
kagid: audit: log integrity violation: line 3: bad MAC
```

### 手動セットアップ

```bash
make build
bin/kagi-ca init  -dir pki
bin/kagi-ca issue -dir pki -kind server -name broker -hosts localhost,127.0.0.1
bin/kagi-ca issue -dir pki -kind agent  -name yata     # 既定7日で失効
bin/kagi-ca issue -dir pki -kind admin  -name ops

cp examples/policy.example.json policy.json
mkdir -p data secrets && openssl rand -base64 32 > secrets/passphrase && chmod 600 secrets/passphrase
KAGI_PASSPHRASE_FILE=secrets/passphrase bin/kagid -pq-only

# 別ターミナル：キーは標準入力から登録（シェル履歴に残さない）
read -s KEY && printf '%s' "$KEY" | bin/kagictl secret put openai-api-key
```

### エージェント側（Python）

```python
client = OpenAI(
    base_url="https://localhost:8443/v1/proxy/openai/v1",
    api_key=token,                      # kagi の短命トークン（本物のキーではない）
    http_client=httpx.Client(cert=("pki/yata.crt", "pki/yata.key"), verify="pki/ca.crt"),
)
```

全体は [`examples/python/agent.py`](examples/python/agent.py) を参照してください。

### Docker / systemd

- `docker compose up -d`：distroless・非root・読み取り専用ルートFS・全ケーパビリティ削除・Docker secrets でパスフレーズを渡す
- `deploy/kagid.service`：`DynamicUser`、`ProtectSystem=strict`、`SystemCallFilter`、`systemd-creds` による暗号化クレデンシャル

## ポリシー

```json
{
  "upstreams": {
    "openai": { "base_url": "https://api.openai.com", "secret": "openai-api-key",
                "inject": { "header": "Authorization", "format": "Bearer {secret}" } }
  },
  "agents": {
    "yata": { "grants": [
      { "upstream": "openai", "max_ttl": "15m", "max_requests": 200,
        "allow": [ { "method": "POST", "path": "/v1/chat/completions" } ] }
    ] }
  }
}
```

未知のフィールドは**読み込みエラー**になります（タイプミスで権限が広がる事故を防ぐため）。`http://` の上流、`Host` ヘッダーへの注入、パス中の `..`、途中のワイルドカードも拒否します。

## API

| メソッド | パス | ロール | 説明 |
|---|---|---|---|
| POST | `/v1/token` | agent | `{"upstream":"openai","ttl":"5m","purpose":"..."}` → 短命トークン |
| ANY | `/v1/proxy/{upstream}/{path...}` | agent | キーを注入して転送 |
| GET | `/v1/secrets/{name}` | agent | `secret` グラントがある場合のみ値を返す（CI用途など） |
| GET/PUT/DELETE | `/v1/admin/secrets[/{name}]` | admin | 秘密の管理 |
| POST | `/v1/admin/revoke` | admin | `{"token_id":"..."}` で即時失効 |
| GET | `/metrics`, `/healthz` | （運用ポートのみ） | 既定で `127.0.0.1:9090` |

## テスト

```bash
make test   # go vet + race detector + coverage
make fuzz   # トークン検証のファジング
make vuln   # govulncheck
```

主な攻撃シナリオのテスト（`internal/broker/broker_test.go` など）：

- エージェント・監査ログのどちらにもキーが現れない
- 許可外のメソッド／パス、`%2F` エンコードやトラバーサルによるすり抜けを拒否し、上流には一切届かない
- 盗んだトークンは、別エージェントでも**同名エージェントの別証明書**でも使えない
- 回数上限・失効・ポリシー削除が即座に効く
- クライアント証明書なし・別CAの証明書はTLSハンドシェイクで拒否
- `-pq-only` で、古典的な鍵交換のみのクライアントを拒否
- ループバック宛の上流（SSRF）を遮断する
- 監査ログの改ざん・削除・並べ替え・フィールド注入・改行によるログインジェクションを検知
- トークン署名の base64 非正規エンコーディング（malleability）を拒否

## 設計上の判断と制約

正直に書いておきます。詳しくは [SECURITY.md](SECURITY.md) を参照してください。

- **暗号プロトコルは自作していません**。通信は標準の TLS 1.3、署名は Ed25519、保存は AES-GCM です。
- **トークン署名鍵は起動ごとに生成**するので、再起動すると全トークンが失効します（数分で切れるトークンなので許容。むしろ安全側）。
- **単一ノード構成**です。冗長化するなら、回数上限と失効リストを Redis などで共有する必要があります。
- **キーの完全な隠蔽はできません**。上流APIの仕様上キーを含むレスポンスを返すケースは伏字化で対処しますが、エージェントが「許可されたAPIを悪用する」こと自体は、許可リストと回数上限で被害を限定するしかありません。
- 本番の秘密管理基盤（HashiCorp Vault / OpenBao、クラウドの Secrets Manager）を置き換えるものではありません。それらの前段に置く「エージェント用ゲートウェイ」という位置づけです。

## ライセンス

MIT
