import socket
import re

HOST = "cns-test.idlab.uantwerpen.be"
PORT = 50001


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError(
            f"XOR requires equal lengths: {len(a)} != {len(b)}"
        )
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------
# The transaction format from format.json:
#
# {"from":"user1","to":"user2","amount": "xxxxxx"}
#
# IMPORTANT:
# xxxxxx is a placeholder. It is NOT necessarily the
# plaintext contained in the server's pending transaction.
# ---------------------------------------------------------

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # -----------------------------------------------------
    # 1. Receive banner until the transaction prompt
    # -----------------------------------------------------
    banner = b""

    while b"Submit the transaction" not in banner:
        chunk = s.recv(4096)

        if not chunk:
            raise ConnectionError("Server closed the connection")

        banner += chunk

    banner_text = banner.decode("utf-8", errors="replace")
    print(banner_text)

    # -----------------------------------------------------
    # 2. Extract the pending transaction ciphertext
    # -----------------------------------------------------
    match = re.search(
        r"Your pending transaction:\s*([0-9a-fA-F]+)",
        banner_text
    )

    if not match:
        raise ValueError("Could not find transaction ciphertext")

    ct_hex = match.group(1)
    ciphertext = bytes.fromhex(ct_hex)

    print("Ciphertext:", ct_hex)
    print("Ciphertext length:", len(ciphertext))

    # -----------------------------------------------------
    # 3. IMPORTANT:
    #
    # The actual plaintext must have the SAME length as
    # the Salsa20 ciphertext.
    #
    # The server ciphertext is 53 bytes.
    #
    # Therefore:
    #
    # {"from":"alice","to":"bob","amount": "XXXXXXXXXXX"}
    #
    # must contain an 11-character amount.
    # -----------------------------------------------------

    prefix = b'{"from":"alice","to":"bob","amount": "'
    suffix = b'"}'

    amount_length = len(ciphertext) - len(prefix) - len(suffix)

    print("Required amount length:", amount_length)

    if amount_length <= 0:
        raise ValueError("Invalid ciphertext/plaintext length")

    # -----------------------------------------------------
    # 4. At this point we need the ACTUAL amount from the
    # pending transaction.
    #
    # We cannot derive it from format.json alone.
    #
    # For testing, enter the amount here.
    # -----------------------------------------------------

    amount = input(
        f"Enter the pending transaction amount "
        f"({amount_length} characters): "
    ).strip()

    if len(amount) != amount_length:
        raise ValueError(
            f"Amount must contain exactly {amount_length} characters, "
            f"but contains {len(amount)}"
        )

    # -----------------------------------------------------
    # 5. Reconstruct the known plaintext
    # -----------------------------------------------------

    known_plaintext = (
        prefix
        + amount.encode("ascii")
        + suffix
    )

    print("Known plaintext:", known_plaintext)
    print("Plaintext length:", len(known_plaintext))

    if len(known_plaintext) != len(ciphertext):
        raise ValueError(
            f"Plaintext/ciphertext mismatch: "
            f"{len(known_plaintext)} != {len(ciphertext)}"
        )

    # -----------------------------------------------------
    # 6. Recover the Salsa20 keystream
    #
    # C = P XOR K
    # K = C XOR P
    # -----------------------------------------------------

    keystream = xor_bytes(ciphertext, known_plaintext)

    print("Keystream:", keystream.hex())

    # -----------------------------------------------------
    # 7. Create the forged transaction.
    #
    # It must have EXACTLY the same length.
    #
    # Change the amount to whatever the challenge expects.
    # -----------------------------------------------------

    forged_amount = input(
        f"Enter forged amount ({amount_length} characters): "
    ).strip()

    if len(forged_amount) != amount_length:
        raise ValueError(
            f"Forged amount must contain exactly "
            f"{amount_length} characters"
        )

    my_plaintext = (
        prefix
        + forged_amount.encode("ascii")
        + suffix
    )

    print("Forged plaintext:", my_plaintext)

    # -----------------------------------------------------
    # 8. Encrypt forged plaintext with recovered keystream
    # -----------------------------------------------------

    forged_ciphertext = xor_bytes(
        keystream,
        my_plaintext
    )

    forged_hex = forged_ciphertext.hex()

    print("Forged ciphertext:")
    print(forged_hex)

    # -----------------------------------------------------
    # 9. Send it to the server
    # -----------------------------------------------------

    s.sendall(forged_hex.encode("ascii") + b"\n")

    response = s.recv(4096)

    print("Server response:")
    print(response.decode("utf-8", errors="replace"))