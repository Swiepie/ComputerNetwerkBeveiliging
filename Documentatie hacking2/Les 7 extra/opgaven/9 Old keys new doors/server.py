# Doe alsof dit Responder B is. Gebruik enkel step3() en step5().
# B onthoudt GEEN oude sessiesleutels (dat is precies de zwakte).
import hashlib, os

_Kb = "90ed274132c2a3aafcfc422d9b5e5bea"
_FLAG = 'cns{old_session_keys_enable_replay}'

def _ks(key, n):
    out, i = b"", 0
    while len(out) < n:
        out += hashlib.sha256(f"{key}:{i}".encode()).digest()
        i += 1
    return out[:n]

def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

_state = {}

def step3(ticket_hex):
    """Ontvang E(Kb, [Ks || IDA]). Antwoord: E(Ks, N2) als hex."""
    ticket = bytes.fromhex(ticket_hex)
    plain = _xor(ticket, _ks(_Kb, len(ticket))).decode()
    ks, ida = plain.split("|IDA=")
    n2 = int.from_bytes(os.urandom(4), "big")
    _state.update(ks=ks, n2=n2, ida=ida)
    return _xor(str(n2).encode(), _ks(ks, len(str(n2)))).hex()

def step5(resp_hex):
    """Ontvang E(Ks, f(N2)) met f(N) = N + 1. Geeft de flag als dat klopt."""
    resp = bytes.fromhex(resp_hex)
    got = _xor(resp, _ks(_state["ks"], len(resp))).decode()
    if got == str(_state["n2"] + 1):
        return "B accepteert " + _state["ida"] + ": " + _FLAG
    return "B weigert."
