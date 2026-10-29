"""
kagi 経由で LLM API を呼ぶエージェントの例。

エージェントのコードには本物の API キーが一切出てこない。
持っているのは「mTLS クライアント証明書」と「数分で失効するトークン」だけ。

    pip install httpx openai
    python agent.py
"""

import os

import httpx
from openai import OpenAI

BROKER = os.environ.get("KAGI_URL", "https://localhost:8443")
PKI = os.environ.get("KAGI_PKI", "pki")

# mTLS: 証明書でエージェントを認証し、ブローカーのサーバー証明書も自前CAで検証する
http = httpx.Client(
    cert=(f"{PKI}/yata.crt", f"{PKI}/yata.key"),
    verify=f"{PKI}/ca.crt",
    timeout=60,
)

# 1) 用途を絞った短命トークンを取得（ポリシー上の上限より長くは発行されない）
resp = http.post(
    f"{BROKER}/v1/token",
    json={"upstream": "openai", "ttl": "5m", "purpose": "ユーザーの質問に回答"},
)
resp.raise_for_status()
tok = resp.json()
print(f"token_id={tok['token_id']} expires_at={tok['expires_at']} max_requests={tok.get('max_requests')}")

# 2) OpenAI SDK の base_url をブローカーに向けるだけ。
#    api_key にはトークンを入れる。ブローカーがこれを本物のキーに差し替えて転送する。
#    トークンは証明書に紐づいているので、漏れても他の端末からは使えない。
client = OpenAI(
    base_url=f"{BROKER}/v1/proxy/openai/v1",
    api_key=tok["token"],
    http_client=http,
)

answer = client.chat.completions.create(
    model="gpt-demo",
    messages=[{"role": "user", "content": "山口県の県庁所在地は？"}],
)
print(answer.choices[0].message.content)

# 3) ポリシーで許可されていないエンドポイントは、たとえプロンプトインジェクションで
#    エージェントが乗っ取られても呼べない（403）。
r = http.get(
    f"{BROKER}/v1/proxy/openai/v1/files",
    headers={"Authorization": f"Bearer {tok['token']}"},
)
print("GET /v1/files ->", r.status_code, r.json())
