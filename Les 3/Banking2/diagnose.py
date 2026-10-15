"""Diagnose which serialization the server uses for its truncated SHA-256."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


SERVER_FP_1 = "0dee4d1f"
SERVER_FP_2 = "159b3a90"

data = json.loads(Path("collision.json").read_text(encoding="utf-8"))
p1 = data["payment1"]
p2 = data["payment2"]


def variants(p):
    """Return dict name -> bytes for many plausible serializations."""
    out = {}
    keys = ["reference", "from_account", "to_account", "amount",
            "currency", "timestamp"]

    # 1) JSON variants
    for sort in (False, True):
        for seps_name, seps in (("compact", (",", ":")),
                                ("default", None)):
            kw = {"sort_keys": sort}
            if seps is not None:
                kw["separators"] = seps
            s = json.dumps(p, **kw)
            tag = f"json sort={sort} seps={seps_name}"
            out[tag] = s.encode()
            out[tag + " +nl"] = (s + "\n").encode()
            out[tag + " +crlf"] = (s + "\r\n").encode()

    # 2) repr/str
    out["repr"] = repr(p).encode()
    out["str"] = str(p).encode()

    # 3) joined fields
    for sep in ("|", ",", ";", ":", "\n", "", " ", "/", ">"):
        joined = sep.join(str(p[k]) for k in keys)
        out[f"join {sep!r}"] = joined.encode()
        out[f"join {sep!r} +nl"] = (joined + "\n").encode()

    # 4) amount variations: int, string, and with different decimals
    for amt in (10, 10.0, "10", "10.0", "10.00", "10.000"):
        q = dict(p)
        q["amount"] = amt
        s = json.dumps(q, separators=(",", ":"))
        out[f"json compact amount={amt!r}"] = s.encode()
        out[f"json compact+nl amount={amt!r}"] = (s + "\n").encode()

    # 5) only the reference
    out["reference only"] = p["reference"].encode()
    out["reference only +nl"] = (p["reference"] + "\n").encode()

    return out


def main():
    v1 = variants(p1)
    v2 = variants(p2)

    algorithms = {
        "sha256": hashlib.sha256,
        "sha1": hashlib.sha1,
        "md5": hashlib.md5,
    }

    for name in v1:
        if name not in v2:
            continue
        for algo_name, algo in algorithms.items():
            h1 = algo(v1[name]).hexdigest()
            h2 = algo(v2[name]).hexdigest()
            for tname, i1, i2 in (
                ("first8", h1[:8], h2[:8]),
                ("last8", h1[-8:], h2[-8:]),
            ):
                if i1 == SERVER_FP_1 and i2 == SERVER_FP_2:
                    print(f"*** MATCH: {algo_name} / {name} / {tname}")
                    print(f"    raw1 = {v1[name]!r}")
                    print(f"    raw2 = {v2[name]!r}")
                    return

    print("Geen exacte match. Gedeeltelijke matches op betaling 1:")
    for name, raw in v1.items():
        for algo_name, algo in algorithms.items():
            if algo(raw).hexdigest()[:8] == SERVER_FP_1:
                print(f"  fp1 match: {algo_name} / {name}")


if __name__ == "__main__":
    main()