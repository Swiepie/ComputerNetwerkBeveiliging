import requests, json

BASE = "http://cns-test.idlab.uantwerpen.be:50007"

r = requests.get(f"{BASE}/challenge")
challenge = r.json()

message = challenge["message"]          # {"action": "view", "role": "user"}
signature = challenge["signature"]

# Send the message EXACTLY as received, byte-for-byte, as the body
r2 = requests.post(
    f"{BASE}/vault",
    data=json.dumps(message),           # try this first
    headers={"Content-Type": "application/json", "X-Signature": signature}
)
print(r2.status_code, r2.text)

raw_text = r.text
print(raw_text)