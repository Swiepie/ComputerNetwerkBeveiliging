

flag_hex = "780e0e4eb4895673e1cc8040d1fcce8f2c3405ee4fd2cf027919d04443713d529ad4db378c7ab46534"
known_hex = "520e5d41bf84177de8ce8749dacad28d793308d406f4fe0e7e09c35b4a281557889adf209b74b5732db8fce5ae11b38a6eaf347e12f33527ef4401184061303fc202316c307892dbb578a49cb051a78436bdde14db8749315aca19d0cc6e85a3d905a4fa9a9bc306d51396f844f22640a88d956adff41d1bdfbf08"
message = "In the beginning the Universe was created. This had made a lot of people very angry and been widely regarded as a bad move."




#vanaf hier komt eigen code
def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

flag_ct = bytes.fromhex(flag_hex)
known_ct = bytes.fromhex(known_hex)
known_pt = message.encode("utf-8")

print(known_pt)

# recover keystream
keystream = xor(known_ct, flag_ct)
# decrypt the flag
flag = xor(flag_ct, keystream)
print("yes")
print(flag)

print(len(known_ct), len(known_pt))  # should match (85 and 85)

# recover keystream
keystream = bytes(c ^ p for c, p in zip(known_ct, known_pt))

# decrypt the flag
flag = bytes(c ^ k for c, k in zip(flag_ct, keystream))
print(flag)