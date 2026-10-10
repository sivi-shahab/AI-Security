"""Official OpenAI and Anthropic SDKs against the test gateway (TestServeForSDK): a block must surface as the SDK's
typed PermissionDeniedError carrying the decision id, a clean call must parse normally."""
import sys
import anthropic
import openai

gw, key = sys.argv[1], "gw-key-chat-0123456789"
secret = "deploy with aws_access_key_id=AKIAIOSFODNN7EXAMPLE and aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

oa = openai.OpenAI(base_url=gw + "/openai/v1", api_key=key, max_retries=0)
try:
    oa.chat.completions.create(model="m", messages=[{"role": "user", "content": secret}])
    sys.exit("openai: block not raised")
except openai.PermissionDeniedError as e:
    print("openai block ->", type(e).__name__, e.status_code, e.response.headers["x-aisec-decision-id"], e.body["code"])
r = oa.chat.completions.create(model="m", messages=[{"role": "user", "content": "opening hours?"}])
print("openai clean ->", type(r).__name__, r.choices[0].message.content[:30])
try:
    oa.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}], stream=True)
    sys.exit("openai: stream refusal not raised")
except openai.BadRequestError as e:
    print("openai stream ->", type(e).__name__, e.status_code)

an = anthropic.Anthropic(base_url=gw + "/anthropic", api_key=key, max_retries=0)
try:
    an.messages.create(model="m", max_tokens=10, messages=[{"role": "user", "content": secret}])
    sys.exit("anthropic: block not raised")
except anthropic.PermissionDeniedError as e:
    print("anthropic block ->", type(e).__name__, e.status_code, e.response.headers["x-aisec-decision-id"], e.body["error"]["type"])
m = an.messages.create(model="m", max_tokens=10, messages=[{"role": "user", "content": "AML red flags?"}])
print("anthropic clean ->", type(m).__name__, m.content[0].text[:30])
