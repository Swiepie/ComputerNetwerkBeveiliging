import hashlib

def ha1(username, realm, password):
    return hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()

def ha2(method, uri):
    return hashlib.md5(f"{method}:{uri}".encode()).hexdigest()

def digest_response(username, realm, password, nonce, method, uri):
    h1 = ha1(username, realm, password)
    h2 = ha2(method, uri)
    return hashlib.md5(f"{h1}:{nonce}:{h2}".encode()).hexdigest()


username = "user"
realm = "PythonRTSP"
nonce = "4874a055c3f4390506d99e6c51a9e3e360cbef8a62abd7079e11faddcb70a38c"              # from your own test server's response
method = "DESCRIBE"
uri = "rtsp://cns-test.idlab.uantwerpen.be:50002/video"

real = "b3539154c5b784bba2c47a1a6c7c4ab0"

with open("rockyou.txt", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        candidate = line.strip()
        if digest_response(username, realm, candidate, nonce, method, uri) == real:
            print(f"Match gevonden: {candidate}")
            break