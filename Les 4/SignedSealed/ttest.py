import requests, json, hashlib, hmac, sys

BASE = "http://cns-test.idlab.uantwerpen.be:50007"

# ---------- 1. Get challenge ----------
ch = requests.get(f"{BASE}/challenge").json()
msg = ch["message"]
sig = ch["signature"]
msg_str = json.dumps(msg)                      # {"action": "view", "role": "user"}
print("message:", msg_str)
print("sig    :", sig)

def post(body, signature, label=""):
    if isinstance(body, str):
        body = body.encode()
    r = requests.post(
        f"{BASE}/vault",
        data=body,
        headers={"Content-Type": "application/json", "X-Signature": signature},
    )
    ok = r.status_code == 200 or "flag" in r.text.lower()
    print(f"[{label:40s}] {r.status_code}: {r.text[:120]}")
    if ok:
        print("\n*** SUCCESS ***\n", r.text)
        sys.exit(0)
    return r

# ---------- 2. Baseline sanity checks ----------
post(msg_str, sig, "original")
post(json.dumps(msg, separators=(",", ":")), sig, "compact")
post(json.dumps(msg, sort_keys=True), sig, "sorted-keys")

# ---------- 3. Trivial tampering (should all fail) ----------
post(json.dumps({"action": "view", "role": "admin"}), sig, "role=admin")
post(json.dumps({"action": "view", "role": "user", "is_admin": True}), sig, "extra is_admin")
post(json.dumps({"action": "admin", "role": "user"}), sig, "action=admin")

# Duplicate keys (Python takes the LAST one)
post('{"action":"view","role":"user","role":"admin"}', sig, "dup role last=admin")
post('{"action":"view","role":"admin","role":"user"}', sig, "dup role first=admin")

# ---------- 4. Is the secret empty or a known word? ----------
for s in ["", "secret", "key", "password", "admin", "test", "flag",
          "s3cr3t", "supersecret", "changeme", "default"]:
    if hashlib.sha256(s.encode() + msg_str.encode()).hexdigest() == sig:
        print(f"\n*** SECRET FOUND (sha256 suffix scheme): {s!r}")
        print("You can now sign any body with:",
              hashlib.sha256(s.encode() + json.dumps({"action":"view","role":"admin"}).encode()).hexdigest())
        sys.exit(0)
    if hmac.new(s.encode(), msg_str.encode(), hashlib.sha256).hexdigest() == sig:
        print(f"\n*** SECRET FOUND (HMAC scheme): {s!r}")
        sys.exit(0)

# ---------- 5. Length-extension attack ----------
try:
    import hashpumpy
except ImportError:
    print("\n[!] pip install hashpumpy  then re-run")
    sys.exit(0)

# These suffixes are what the server will see appended after the SHA-256 padding.
# The parser has to be lenient enough to still read a role=admin object.
appends = [
    b'"role": "admin"',
    b',"role": "admin"',
    b',"role":"admin"',
    b'{"action": "view", "role": "admin"}',
    b'{"action":"view","role":"admin"}',
]

print("\nBrute-forcing secret length (0..64) with length extension...")
for keylen in range(0, 65):
    for app in appends:
        try:
            new_sig, new_body = hashpumpy.hashpump(sig, msg_str.encode(), app, keylen)
        except Exception:
            continue
        r = requests.post(
            f"{BASE}/vault",
            data=new_body,
            headers={"Content-Type": "application/json", "X-Signature": new_sig},
        )
        if r.status_code == 200 or "flag" in r.text.lower():
            print(f"\n*** LENGTH EXTENSION SUCCEEDED ***")
            print("keylen =", keylen)
            print("append =", app)
            print("body   =", new_body)
            print("sig    =", new_sig)
            print(r.text)
            sys.exit(0)
        if "invalid signature" not in r.text.lower():
            # Server understood the signature but rejected on other grounds —
            # very interesting, print it.
            print(f"  keylen={keylen} append={app!r} -> {r.status_code} {r.text[:80]}")

print("\nLength extension didn't succeed with strict-JSON parsers.")
print("If you saw 'Invalid JSON' above, that confirms sha256(secret||body) but strict parsing.")