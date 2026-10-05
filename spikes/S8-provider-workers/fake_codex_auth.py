#!/usr/bin/env python3
"""Print a ChatGPT-mode auth.json for Codex CLI holding only placeholders.
The id_token is an unsigned JWT with synthetic claims; nothing here is real."""
import base64, json, time, datetime
def b64(o): return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
claims = {"email": "s8@example.invalid", "exp": int(time.time()) + 86400,
          "https://api.openai.com/auth": {"chatgpt_plan_type": "plus", "chatgpt_account_id": "acct-S8",
                                          "chatgpt_user_id": "user-S8"}}
jwt = b64({"alg": "none", "typ": "JWT"}) + "." + b64(claims) + ".sig"
print(json.dumps({"OPENAI_API_KEY": None, "tokens": {
    "id_token": jwt, "access_token": "PLACEHOLDER-S8-access",
    "refresh_token": "PLACEHOLDER-S8-refresh", "account_id": "acct-S8"},
    "last_refresh": datetime.datetime.now(datetime.timezone.utc).isoformat()}, indent=1))
