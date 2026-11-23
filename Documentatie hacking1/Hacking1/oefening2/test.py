hash = "2647457a3b8ecb1cfedef2ce42958eeaa0016bb097c81b0948913d08e619a42e59f30e"

def rol(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xff

def ror(x, n):
    return ((x >> n) | (x << (8 - n))) & 0xff

def bettererhash(msg):
    s = bytearray(msg.encode())
    for rnd in range(8):
        for i in range(len(s)):
            x = s[i]
            x = rol(x ^ ((rnd * 23 + i * 17) & 0xff),
                    ((rnd ^ i) & 7))
            x = (x + ((rnd + 1) * (i + 3))) & 0xff
            s[i] = x
        for i in range(1, len(s)):
            s[i] ^= rol(s[i - 1], i & 7)
    return s.hex()

def reverse_hash(msg):
    state = bytearray.fromhex(msg)
    for rnd in range(7, -1, -1):
        for i in range(len(state) - 1, 0, -1):
            state[i] ^= ror(state[i - 1], i & 7)

        for i in range(len(state) - 1, -1, -1):
            x = (state[i] - ((rnd + 1) * (i + 3))) & 0xff
            x = ror(x ^ ((rnd * 23 + i * 17) & 0xff),((rnd ^ i) & 7))
            state[i] = x
    return state.decode('ascii', errors='ignore')

print(reverse_hash(hash))


def reverse_hash2(msg):
    state = bytearray.fromhex(msg)


    for rnd in range(7, -1, -1):


        for i in range(len(state) - 1, 0, -1):
            state[i] ^= rol(state[i - 1], i & 7)
        for i in range(len(state) - 1, -1, -1):
            x = (state[i] - ((rnd + 1) * (i + 3))) & 0xff
            x = ror(x, ((rnd ^ i) & 7)) ^ ((rnd * 23 + i * 17) & 0xff)
            state[i] = x

    return state.decode('ascii', errors='ignore')
print(reverse_hash2(hash))