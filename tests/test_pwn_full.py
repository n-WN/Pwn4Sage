import os
import sys
import ssl as _ssl
import socket
import threading
import time
import tempfile
import pathlib
import re
import socket
import threading

import pytest

# Ensure local pwn.py is imported
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pwn  # type: ignore
from pwn import context, process, remote, listen, server, PTY, args  # type: ignore


def setup_module(module):
    # keep tests fast and verbose
    context(timeout=1.0, log_level="info", log_timestamps=True)


def _strip_ansi(b: bytes) -> bytes:
    return re.sub(br"\x1b\[[0-9;?]*[a-zA-Z]", b"", b)


def test_sendafter_strict_and_compat():
    print("[FULL] send*after strict vs compat")
    code = (
        "import sys\n"
        "sys.stdout.write('Your name?\\n')\n"
        "sys.stdout.flush()\n"
        "line = sys.stdin.readline()\n"
        "sys.stdout.write('HI:'+line)\n"
        "sys.stdout.flush()\n"
    )
    # strict mode: must match full 'Your name?\n'
    with process([sys.executable, "-u", "-c", code]) as io:
        got = io.recvline(timeout=1.0)
        print("prompt:", got)
        with context.local(consume_delim_newline=False):
            io.sendlineafter(b"Your name?\n", b"alice")
        reply = io.recvline(timeout=1.0)
        print("reply:", reply)
        assert reply == b"HI:alice\n"

    # compat mode: allow matching 'Your name?' then auto-swallow one newline
    with process([sys.executable, "-u", "-c", code]) as io:
        got = io.recvline(timeout=1.0)
        print("prompt:", got)
        with context.local(consume_delim_newline=True):
            io.sendlineafter(b"Your name?", b"bob")
        reply = io.recvline(timeout=1.0)
        print("reply:", reply)
        assert reply == b"HI:bob\n"


def test_wiretap_global_and_tube(tmp_path: pathlib.Path):
    print("[FULL] wiretap global + per tube")
    tap_global = tmp_path / "global.tap"
    tap_local = tmp_path / "local.tap"
    with context.local(wiretap=str(tap_global)):
        code = (
            "import sys\n"
            "sys.stdout.write('READY\\n')\n"
            "sys.stdout.flush()\n"
            "sys.stdout.write(sys.stdin.readline())\n"
            "sys.stdout.flush()\n"
        )
        io = process([sys.executable, "-u", "-c", code])
        try:
            assert io.recvline() == b"READY\n"
            io.wiretap(str(tap_local))
            io.sendline(b"PING")
            assert io.recvline() == b"PING\n"
        finally:
            io.close()
    # verify taps written
    assert tap_global.exists() and tap_global.stat().st_size > 0
    assert tap_local.exists() and tap_local.stat().st_size > 0


def test_process_pty_roundtrip():
    print("[FULL] process PTY echo")
    # Use a tiny Python REPL-like that echoes lines back; PTY may echo input
    code = (
        "import sys\n"
        "sys.stdout.write('ok\\n')\n"
        "sys.stdout.flush()\n"
        "while True:\n"
        "    line = sys.stdin.readline()\n"
        "    if not line: break\n"
        "    sys.stdout.write('resp:'+line)\n"
        "    sys.stdout.flush()\n"
    )
    io = process([sys.executable, "-u", "-c", code], tty=True)
    try:
        ln = _strip_ansi(io.recvline())
        print("pty hello:", ln)
        # Accept CRLF from PTY
        if ln.endswith(b"\r\n"):
            ln = ln.replace(b"\r\n", b"\n")
        assert ln == b"ok\n"
        io.sendline(b"XYZ")
        # PTY may echo input back as a line; read until the response line
        first = _strip_ansi(io.recvline())
        if first.strip() == b"XYZ":
            out = _strip_ansi(io.recvline())
        else:
            out = first
        print("pty resp:", out)
        if out.endswith(b"\r\n"):
            out = out.replace(b"\r\n", b"\n")
        assert out == b"resp:XYZ\n"
    finally:
        io.close()


def test_listen_ipv4_and_fromsocket():
    print("[FULL] listen IPv4 + fromsocket")
    srv = listen("127.0.0.1", 0)
    def server():
        cli = srv.wait_for_connection(timeout=1.0)
        try:
            data = cli.recvline(timeout=1.0)
            cli.send(b"E:" + data)
        finally:
            cli.close()

    th = threading.Thread(target=server, daemon=True)
    th.start()
    # client via normal remote
    r = remote("127.0.0.1", srv.lport, timeout=1.0)
    assert r.recv(0, timeout=0.1) == b""  # nothing yet
    r.sendline(b"abc")
    assert r.recvline(timeout=1.0) == b"E:abc\n"
    r.close()

    # client via fromsocket
    th = threading.Thread(target=server, daemon=True)
    th.start()
    s = socket.socket()
    s.connect(("127.0.0.1", srv.lport))
    s.sendall(b"zzz\n")
    r2 = pwn.remote.fromsocket(s)  # type: ignore
    assert r2.recvline(timeout=1.0) == b"E:zzz\n"
    r2.close()
    srv.close()


def test_remote_udp_roundtrip():
    print("[FULL] remote UDP roundtrip")
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    stop = threading.Event()

    def server():
        try:
            data, addr = srv.recvfrom(4096)
            print("[UDP srv] recv:", data)
            srv.sendto(b"PONG\n", addr)
        finally:
            stop.set()
            srv.close()

    threading.Thread(target=server, daemon=True).start()

    cli = remote("127.0.0.1", port, typ="udp", timeout=2.0)
    try:
        cli.sendline(b"PING")
        out = cli.recvline(timeout=2.0)
        print("[UDP cli] recv:", out)
        assert out == b"PONG\n"
    finally:
        cli.close()
    stop.wait(1.0)


def test_listen_udp_roundtrip():
    print("[FULL] listen UDP roundtrip")
    lst = listen("127.0.0.1", 0, typ="udp")

    def server():
        tube = lst.wait_for_connection(timeout=2.0)
        try:
            tube.recvline(timeout=1.0)
            tube.sendline(b"UDP-OK")
        finally:
            tube.close()

    threading.Thread(target=server, daemon=True).start()

    cl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cl_sock.sendto(b"HELLO\n", ("127.0.0.1", lst.lport))
    data, _ = cl_sock.recvfrom(4096)
    print("[UDP listen client] recv:", data)
    assert data == b"UDP-OK\n"
    cl_sock.close()
    lst.close()


def test_server_callback_and_next_connection():
    print("[FULL] server helper callback + next_connection")

    messages = []

    def cb(tube):
        print("[server cb] reading")
        data = tube.recvline()
        messages.append(data)
        tube.sendline(b"ACK")

    srv = server(0, bindaddr="127.0.0.1", callback=cb)

    # first client handled via callback thread
    cli1 = remote("127.0.0.1", srv.lport)
    cli1.sendline(b"cb-client")
    assert cli1.recvline(timeout=1.0) == b"ACK\n"
    cli1.close()

    # Allow callback thread to settle
    import time
    time.sleep(0.1)

    # second client retrieved manually via next_connection while callback is None
    srv.callback = None
    cli2 = remote("127.0.0.1", srv.lport)
    srv_conn = srv.next_connection(timeout=2.0)
    srv_conn.sendline(b"srv")
    assert cli2.recvline(timeout=1.0) == b"srv\n"
    cli2.close()
    srv_conn.close()
    srv.close()

    assert messages == [b"cb-client\n"]


@pytest.mark.skipif(not socket.has_ipv6, reason="No IPv6 support")
def test_listen_ipv6_roundtrip():
    print("[FULL] listen IPv6 roundtrip")
    srv = listen("::1", 0, fam="ipv6")
    def server():
        cli = srv.wait_for_connection(timeout=2.0)
        try:
            cli.sendline(b"V6")
        finally:
            cli.close()

    threading.Thread(target=server, daemon=True).start()
    r = remote("::1", srv.lport, fam="ipv6", timeout=2.0)
    try:
        assert r.recvline(timeout=2.0) == b"V6\n"
    finally:
        r.close(); srv.close()


def _start_tls_echo_server(host="127.0.0.1"):
    # minimal self-signed cert/key (testing only)
    # generate ephemeral self-signed via openssl cli (skip if unavailable)
    if os.system("command -v openssl >/dev/null 2>&1") != 0:
        pytest.skip("openssl not available for TLS test")
    tmpdir = tempfile.mkdtemp()
    cert_path = os.path.join(tmpdir, "cert.pem")
    key_path = os.path.join(tmpdir, "key.pem")
    os.system(
        f"openssl req -x509 -nodes -newkey rsa:2048 -subj /CN=localhost -keyout {key_path} -out {cert_path} -days 1 >/dev/null 2>&1"
    )

    srv_sock = socket.socket()
    srv_sock.bind((host, 0))
    srv_sock.listen(5)
    lport = srv_sock.getsockname()[1]

    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

    def run():
        try:
            conn, addr = srv_sock.accept()
            with ctx.wrap_socket(conn, server_side=True) as tls_conn:
                tls_conn.sendall(b"READY\n")
                data = tls_conn.recv(4096)
                if data:
                    tls_conn.sendall(data)
        except Exception as exc:
            print("[TLS srv] exception:", exc)
        finally:
            srv_sock.close()
            try:
                os.unlink(cert_path); os.unlink(key_path)
            except Exception:
                pass

    threading.Thread(target=run, daemon=True).start()
    return lport


def test_remote_tls_local_echo():
    print("[FULL] TLS local echo with unverified client context")
    port = _start_tls_echo_server()
    # Use unverified context for test self-signed server
    ctx = _ssl._create_unverified_context()
    r = remote("127.0.0.1", port, ssl=True, ssl_context=ctx, sni=False, timeout=2.0)
    try:
        # server first line
        first = r.recvline(timeout=2.0)
        print("tls first:", first)
        r.send(b"HELLO\n")
        out = r.recvline(timeout=2.0)
        print("tls echo:", out)
        assert out == b"HELLO\n"
    finally:
        r.close()


def test_args_magic_env(monkeypatch):
    print("[FULL] args magic via env + argv")
    # Reparse with env + argv tokens
    monkeypatch.setenv("PWNLIB_DEBUG", "1")
    monkeypatch.setenv("PWNLIB_TIMEOUT", "0.7")
    argv = [sys.argv[0], "A=1", "REMOTE"]
    monkeypatch.setattr(sys, "argv", argv, raising=False)
    # Create a fresh args instance and apply
    _Args = pwn.__dict__["_Args"]  # type: ignore
    pwn.args = _Args()
    print("args store:", pwn.args)
    assert pwn.args.A == "1"
    assert pwn.args.REMOTE == "1"
    assert context.log_level == "debug"  # DEBUG applied
    assert context.timeout == 0.7
