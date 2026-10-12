from Crypto.Cipher import DES

ciphertext_hex = "74eb40cf03b84d0bc4cd2c6e0fe97fb4e70546d3e09c530d35b344e530351bac"
ciphertext = bytes.fromhex(ciphertext_hex)

namespace = "IOTDEV"
found = False

print("Searching for key variants...")

# test 100 opties
for i in range(100):
    suffix = f"{i:02d}"
    candidate_key = (namespace + suffix).encode('ascii')

    cipher = DES.new(candidate_key, DES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
        # is het in ascii
        if all(32 <= b < 127 for b in decrypted[:16]):
            print(f"key: {candidate_key}")
            print(f"Decrypted Text: {decrypted.decode('utf-8', errors='ignore')}")
            found = True
            break
    except Exception:
        continue
