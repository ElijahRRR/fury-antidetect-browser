#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Bogdan Shapovalov and the Fury authors
"""What a proxy actually answers, byte by byte, for one host:port:user:pass line.

Prints every reply of the SOCKS5 handshake and of an HTTP CONNECT, once with
the login as given and once with a `__...` suffix cut off, so a check that says
"failed parsing server response" can be read against the bytes behind it.
The password is never printed.

Usage: python3 tools/proxy-probe/probe.py 'host:port:user:pass'
"""

import socket
import sys

TARGET = b"ipinfo.io"


def recv_some(s, n=512):
    try:
        return s.recv(n)
    except socket.timeout:
        return b"(silence)"


def socks5(host, port, user, pw):
    print(f"\n== SOCKS5, login {user!r}")
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(b"\x05\x02\x00\x02")
    r = recv_some(s)
    print(f"  greeting reply: {r.hex(' ')}")
    if r[:2] == b"\x05\x02":
        u, p = user.encode(), pw.encode()
        s.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
        r = recv_some(s)
        print(f"  login reply:    {r.hex(' ')}")
        if len(r) < 2 or r[1] != 0:
            s.close()
            return
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(TARGET)]) + TARGET + (443).to_bytes(2, "big"))
    r = recv_some(s)
    print(f"  CONNECT reply:  {r.hex(' ')}  ({len(r)} bytes)")
    s.close()


def http(host, port, user, pw):
    import base64
    print(f"\n== HTTP CONNECT, login {user!r}")
    s = socket.create_connection((host, port), timeout=10)
    cred = base64.b64encode(f"{user}:{pw}".encode()).decode()
    s.sendall(f"CONNECT ipinfo.io:443 HTTP/1.1\r\nHost: ipinfo.io:443\r\n"
              f"Proxy-Authorization: Basic {cred}\r\n\r\n".encode())
    first = recv_some(s).split(b"\r\n")[0]
    print(f"  reply: {first!r}")
    s.close()


def main():
    host, port, user, pw = sys.argv[1].strip().split(":", 3)
    port = int(port)
    logins = [user] + ([user.split("__")[0]] if "__" in user else [])
    for u in logins:
        for f in (socks5, http):
            try:
                f(host, port, u, pw)
            except Exception as e:
                print(f"  failed: {e}")


if __name__ == "__main__":
    main()
