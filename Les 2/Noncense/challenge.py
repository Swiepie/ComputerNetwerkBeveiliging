from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter

def encrypt(key, nonce, msg):
    ctr = Counter.new(64, prefix=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(msg)

#vanaf hier komt eigen code
def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

flag_hex = "def52b3b54f25097f0d90ff8356ba757801d10e63dcb0f190eccfac3ce23bd5a5bd306cb5c"
known_hex = "fcf83b2f47f34aa6f48d09c87b65a558c5290cec3fd64a2a06c8d687c02bfa5e5fd512cc4854686920f59867edc05aaf9a21560e359928e343cdd4b6ea3ce69267e267a51b2b25522a83d210ca3fc89a684f399e6a"
message = "According to all known laws of aviation, there is no way a bee should be able to fly."

flag_ct = bytes.fromhex(flag_hex)
known_ct = bytes.fromhex(known_hex)
known_pt = message.encode("utf-8")

print(known_pt)

# recover keystream
keystream = xor(known_ct, flag_ct)
# decrypt the flag
flag = xor(flag_ct, keystream)
print(flag)

