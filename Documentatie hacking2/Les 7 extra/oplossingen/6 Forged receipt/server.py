# Doe alsof dit een server op afstand is: gebruik enkel sign() en verify().
_d = 780156942673948773916470227127112061303177411424278982202100238235772285544854745041454010249298728704226534769299281056883660638682961799460099852679793
_n = 5440428341351625962562641974380670691809569909822618818533628784130432887609552275047200787554218699656745573407644350626847172363919047813156328648862687
_e = 65537
TARGET = 417479660208253227052684296467331568495883539794      # = int.from_bytes(b"I owe Siebe 1000 EUR", "big")
_FLAG = b'cns{sign_the_hash_not_the_message}'

def sign(m):
    """Tekent elk getal m behalve TARGET (ruwe RSA, zonder hash of padding)."""
    if m % _n == TARGET:
        raise ValueError("Dat bericht teken ik niet.")
    return pow(m, _d, _n)

def verify(sig):
    """Geeft de flag terug als sig een geldige handtekening is op TARGET."""
    if pow(sig, _e, _n) == TARGET:
        return _FLAG
    return None
