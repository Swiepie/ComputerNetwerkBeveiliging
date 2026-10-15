"""Find and submit two payments with the same truncated SHA-256 fingerprint."""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HOST = "cns-test.idlab.uantwerpen.be"
PORT = 50003
DEFAULT_TIMEOUT = 100.0
DEFAULT_SEND_DELAY = 2  # seconden tussen elke send

TRANSACTION_FILE = Path(__file__).with_name("transaction.json")
COLLISION_FILE = Path(__file__).with_name("collision.json")

FINGERPRINT_HEX_LENGTH = 8


def make_payment() -> dict[str, Any]:
    """Create a valid payment whose reference is unique for every attempt."""
    return {
        "reference": f"PAY-{uuid.uuid4().hex}",
        "from_account": "SIM-BE68539007547034",
        "to_account": "SIM-BE71096123456769",
        "amount": 10.00,
        "currency": "EUR",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def save_transaction(payment: dict[str, Any]) -> None:
    TRANSACTION_FILE.write_text(
        json.dumps(payment, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def local_fingerprint(payment: dict[str, Any]) -> str:
    """Truncated SHA-256 of the server's canonical JSON encoding."""
    raw = json.dumps(payment, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:FINGERPRINT_HEX_LENGTH]

def receive_until(sock: socket.socket, marker: bytes) -> str:
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    return data.decode("utf-8", errors="replace")


def receive_all(sock: socket.socket) -> str:
    data = bytearray()
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data.extend(chunk)
    return data.decode("utf-8", errors="replace")


def submit_collision(payment1: dict[str, Any],
                     payment2: dict[str, Any],
                     timeout: float,
                     send_delay: float) -> str:
    """Submit the colliding records in the server's final validation flow.

    Er wordt `send_delay` seconden gewacht tussen elke send en tussen
    het ontvangen van de prompts en het verzenden van de betaling.
    """
    with socket.create_connection((HOST, PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)

        # Wacht op "Payment 1:" prompt
        receive_until(sock, b"Payment 1:")
        time.sleep(send_delay)

        # Verstuur betaling 1
        sock.sendall((json.dumps(payment1, separators=(",", ":")) + "\n").encode())
        time.sleep(send_delay)

        # Wacht op "Payment 2:" prompt
        receive_until(sock, b"Payment 2:")
        time.sleep(send_delay)

        # Verstuur betaling 2
        sock.sendall((json.dumps(payment2, separators=(",", ":")) + "\n").encode())
        time.sleep(send_delay)

        # Lees het uiteindelijke antwoord
        return receive_all(sock)


def find_collision(delay: float, timeout: float, send_delay: float) -> None:
    seen: dict[str, dict[str, Any]] = {}
    attempts = 0

    while True:
        payment = make_payment()
        save_transaction(payment)
        fingerprint = local_fingerprint(payment)
        attempts += 1
        print(f"Poging {attempts}: {fingerprint} ({payment['reference']})", flush=True)

        previous = seen.get(fingerprint)
        if previous is not None and previous != payment:
            COLLISION_FILE.write_text(
                json.dumps(
                    {"fingerprint": fingerprint,
                     "payment1": previous,
                     "payment2": payment},
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            result = submit_collision(previous, payment, timeout, send_delay)
            print(f"Botsing gevonden; finale serverrespons: {result.strip()}")
            return

        seen[fingerprint] = payment
        if delay:
            time.sleep(delay)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--delay", type=float, default=0.0,
                        help="seconden wachten tussen pogingen (standaard: 0)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="socket-timeout in seconden (standaard: 10)")
    parser.add_argument("--send-delay", type=float, default=DEFAULT_SEND_DELAY,
                        help="seconden wachten tussen elke send "
                             f"(standaard: {DEFAULT_SEND_DELAY})")
    args = parser.parse_args()
    find_collision(delay=args.delay,
                   timeout=args.timeout,
                   send_delay=args.send_delay)


if __name__ == "__main__":
    main()