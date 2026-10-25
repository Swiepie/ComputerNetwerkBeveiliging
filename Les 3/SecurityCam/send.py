import socket
import hashlib
import re

HOST = 'cns-test.idlab.uantwerpen.be'
PORT = 50002
USERNAME = "user"
PASSWORD = "camera123456789"
BASE_URI = f"rtsp://{HOST}:{PORT}/video"

def md5(data: str) -> str:
    return hashlib.md5(data.encode()).hexdigest()

def build_digest_header(method, uri, realm, nonce):
    ha1 = md5(f"{USERNAME}:{realm}:{PASSWORD}")
    ha2 = md5(f"{method}:{uri}")
    response = md5(f"{ha1}:{nonce}:{ha2}")
    return (
        f'Digest username="{USERNAME}", realm="{realm}", '
        f'nonce="{nonce}", uri="{uri}", response="{response}"'
    )

def send_request(s, req):
    s.sendall(req.encode())
    data = s.recv(8192)
    return data.decode(errors="replace")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # --- DESCRIBE (no auth) to get the challenge ---
    cseq = 1
    req = f"DESCRIBE {BASE_URI} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n"
    banner = send_request(s, req)
    print(banner)

    realm = re.search(r'realm="([^"]+)"', banner).group(1)
    nonce = re.search(r'nonce="([^"]+)"', banner).group(1)

    # --- DESCRIBE (with auth) ---
    cseq += 1
    auth = build_digest_header("DESCRIBE", BASE_URI, realm, nonce)
    req = (
        f"DESCRIBE {BASE_URI} RTSP/1.0\r\n"
        f"CSeq: {cseq}\r\n"
        f"Authorization: {auth}\r\n\r\n"
    )
    describe_resp = send_request(s, req)
    print(describe_resp)

    # --- SETUP (with auth), interleaved transport over this TCP socket ---
    track_uri = f"{BASE_URI}/trackID=0"
    cseq += 1
    auth = build_digest_header("SETUP", track_uri, realm, nonce)
    req = (
        f"SETUP {track_uri} RTSP/1.0\r\n"
        f"CSeq: {cseq}\r\n"
        f"Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"
        f"Authorization: {auth}\r\n\r\n"
    )
    setup_resp = send_request(s, req)
    print(setup_resp)

    session = re.search(r'Session:\s*([^\r\n;]+)', setup_resp).group(1)

    # --- PLAY (with auth) ---
    cseq += 1
    auth = build_digest_header("PLAY", BASE_URI, realm, nonce)
    req = (
        f"PLAY {BASE_URI} RTSP/1.0\r\n"
        f"CSeq: {cseq}\r\n"
        f"Session: {session}\r\n"
        f"Authorization: {auth}\r\n\r\n"
    )
    play_resp = send_request(s, req)
    print(play_resp)



    # From here, RTP packets (interleaved frames prefixed with '$')
    # will start arriving on this same socket if PLAY succeeded.

    import time

    print("Recording for 5 seconds...")
    s.settimeout(1.0)  # avoid blocking forever on recv
    start = time.time()
    with open("stream.raw", "wb") as f:
        while time.time() - start < 5:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                break
            f.write(chunk)
    print("Done recording.")