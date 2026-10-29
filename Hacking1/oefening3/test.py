def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def recover_via_nonce_reuse(known_ct, known_pt, target_ct):
    keystream = xor_bytes(known_ct, known_pt)
    n = min(len(target_ct), len(keystream))
    return xor_bytes(target_ct[:n], keystream[:n])