def rol(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xff

def better_hash(msg):
    state = bytearray(msg.encode())

    for rnd in range(8):

        for i in range(len(state)):
            state[i] ^= (rnd * 41 + i * 17) & 0xff
            state[i] = rol(state[i], (rnd + i) & 7)

        for i in range(1, len(state)):
            state[i] ^= state[i - 1]

        state = state[1:] + state[:1]

    return state.hex()
FLAG = "5f070b54361613bca31a123e95321cff154ba64f549bb34fdc7688f10efb569aed4ccbd6ba"
flaginflag = "7f91c6f8c3d14af8b9f52d6b7f6e13c4"
print(better_hash(FLAG))

def ror(x, n):
    return ((x >> n) | (x << (8 - n))) & 0xff
def reverse_hash(msg):
    state = bytearray.fromhex(msg)

    for rnd in range(7, -1, -1):
        state = state[-1:] + state[:-1] #dit is naar rechts draaien, dus minnen niet vergeten

        for i in range(len(state)-1, 0, -1):
            state[i] ^= state[i-1]

        for i in range(len(state)-1, -1, -1):
            state[i] =  ror(state[i], (rnd + i) & 7)
            state[i] ^= (rnd * 41 + i * 17) & 0xff

    return state.decode('ascii', errors='ignore')

print(reverse_hash(FLAG))
print(reverse_hash(flaginflag))