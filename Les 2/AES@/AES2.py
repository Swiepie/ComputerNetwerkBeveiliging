from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import struct

data = open("enc.bmp", "rb").read()
promo_hex = "df7c7dfbd5e1ba2af108d658132d5f20d34de27da16375ceabd7a79cbfe738244027a4a0b26ec498a2c223a545b9567c20bf423bb38514e6cd6f043ab9e23a84ffa6745294c224068e1cffd9e8c9e294"
promo = bytes.fromhex(promo_hex)

# known ciphertext: first encrypted block (offset 54)
known_ct = data[54:70]

# candidate plaintexts: R, G, B, A masks (little-endian)
candidates = {
    "BGRA": struct.pack("<4I", 0x00FF0000, 0x0000FF00, 0x000000FF, 0xFF000000),
    "RGBA": struct.pack("<4I", 0x000000FF, 0x0000FF00, 0x00FF0000, 0xFF000000),
    "ARGB-ish": struct.pack("<4I", 0xFF000000, 0x00FF0000, 0x0000FF00, 0x000000FF),
}

def make_key(k):
    return k.to_bytes(3, "big") + b"\x00" * 13

def mitm(known_pt, known_ct):
    # forward table: E_K1(P) -> k1
    table = {}
    for k1 in range(2**20):
        mid = AES.new(make_key(k1), AES.MODE_ECB).encrypt(known_pt)
        table[mid] = k1
    # backward: D_K2(C), look for a match
    for k2 in range(2**20):
        mid = AES.new(make_key(k2), AES.MODE_ECB).decrypt(known_ct)
        if mid in table:
            return table[mid], k2
    return None

for name, pt in candidates.items():
    print("trying", name)
    res = mitm(pt, known_ct)
    if res:
        k1, k2 = res
        print("found:", k1, k2)
        break
else:
    raise SystemExit("no match, check your plaintext guess")

c1 = AES.new(make_key(k1), AES.MODE_ECB)
c2 = AES.new(make_key(k2), AES.MODE_ECB)

# decrypt promo code: undo K2 first, then K1
plain = c1.decrypt(c2.decrypt(promo))
try:
    plain = unpad(plain, 16)
except ValueError:
    pass
print(plain)

# optional: decrypt the image to verify the keys
body = c1.decrypt(c2.decrypt(data[54:]))
with open("dec.bmp", "wb") as f:
    f.write(data[:54] + body[:9300])