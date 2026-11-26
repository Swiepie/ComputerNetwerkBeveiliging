#!/usr/bin/env python3
"""Starter for the Courier challenge"""
import hashlib
import requests

BASE = "http://cns-test.idlab.uantwerpen.be:50013"


def get(path):
    return requests.get(BASE + path, timeout=10).json()


def post(path, body=None):
    return requests.post(BASE + path, json=body or {}, timeout=10).json()


def xor_stream(data: bytes, s: int) -> bytes:
    """Encrypts or decrypts `data` with the keystream derived from the shared secret s."""
    keystream = hashlib.shake_256(str(s).encode()).digest(len(data))
    return bytes(a ^ b for a, b in zip(data, keystream))


params = get("/params")
p, g = params["p"], params["g"]

# Your work starts here.
