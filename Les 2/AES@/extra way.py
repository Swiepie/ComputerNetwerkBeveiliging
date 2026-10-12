from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from collections import Counter

data = open("enc.bmp", "rb").read()
promo = bytes.fromhex(
    "df7c7dfbd5e1ba2af108d658132d5f20d34de27da16375ceabd7a79cbfe738244027a4a0b26ec498a2c223a545b9567c20bf423bb38514e6cd6f043ab9e23a84ffa6745294c224068e1cffd9e8c9e294"
)

HEADER = 54  # bytes before the encrypted part starts
enc = data[HEADER:]
blocks = [enc[i:i + 16] for i in range(0, len(enc), 16)]

def key(k):
    return k.to_bytes(3, "big") + b"\x00" * 13

def mitm(known_pt, known_ct):
    # forward: E_K1(known_pt) -> k1
    table = {}
    for k1 in range(2**20):
        table[AES.new(key(k1), AES.MODE_ECB).encrypt(known_pt)] = k1
    # backward: D_K2(known_ct), look for the same middle value
    for k2 in range(2**20):
        mid = AES.new(key(k2), AES.MODE_ECB).decrypt(known_ct)
        if mid in table:
            return table[mid], k2
    return None

# guesses: the most common ciphertext block is probably a flat colour
common_ct = Counter(blocks).most_common(1)[0][0]
guesses = [
    ("all zeros", bytes(16), common_ct),
    ("all 0xff", b"\xff" * 16, common_ct),
]

for name, pt, ct in guesses:
    print("trying guess:", name)
    result = mitm(pt, ct)
    if not result:
        continue

    k1, k2 = result
    print("keys found:", k1, k2)
    c1 = AES.new(key(k1), AES.MODE_ECB)
    c2 = AES.new(key(k2), AES.MODE_ECB)

    # decrypt promo code: undo K2 first, then K1
    try:
        print("promo code:", unpad(c1.decrypt(c2.decrypt(promo)), 16).decode())
    except ValueError:
        print("bad padding, probably a false match, trying next guess")
        continue

    # also decrypt the image to verify
    body = c1.decrypt(c2.decrypt(enc))
    with open("dec.bmp", "wb") as f:
        f.write(data[:HEADER] + body[:9300])
    print("image saved as dec.bmp")
    break
else:
    print("no guess worked, use the header method (BITMAPV5 colour masks) instead")