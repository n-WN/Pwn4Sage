import threading
import time
import sys
import os
import pprint

# Ensure we import local pwn.py
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from pwn import context, process, remote, listen  # type: ignore


def test_process_echo_basic():
    code = (
        "import sys\n"
        "import os\n"
        "import time\n"
        "sys.stdout.write('READY\\n')\n"
        "sys.stdout.flush()\n"
        "for line in sys.stdin:\n"
        "    sys.stdout.write('ECHO:' + line)\n"
        "    sys.stdout.flush()\n"
    )

    print("[TEST] Launching echo process...")
    p = process([sys.executable, "-u", "-c", code])
    try:
        ready = p.recvline(timeout=2.0)
        print("[TEST] ready:", ready)
        assert ready.endswith(b"READY\n")

        p.sendline(b"hello")
        out = p.recvline(timeout=2.0)
        print("[TEST] echo hello:", out)
        assert out == b"ECHO:hello\n"

        # test sendafter / recvuntil
        p.sendafter(b"ECHO:", b"world\n")
        line = p.recvline(timeout=2.0)
        print("[TEST] echo world:", line)
        assert line == b"ECHO:world\n"

        # Note: the child reads line-based; don't use recvn here
    finally:
        p.close()


def test_remote_listen_roundtrip():
    # Use small timeouts so tests fail fast on errors
    context(timeout=2.0, log_level="info", log_timestamps=True)

    print("[TEST] Starting listener...")
    server = listen("127.0.0.1", 0)
    print(f"[TEST] Listening on {server.lhost}:{server.lport}")

    def server_thread():
        print("[TEST][server] waiting for connection...")
        cli = server.wait_for_connection(timeout=3.0)
        try:
            cli.sendline(b"WELCOME")
            name = cli.recvline_contains(b"name", timeout=2.0)
            print("[TEST][server] got name line:", name)
            assert b"name" in name
            cli.sendline(b"Your name?")
            who = cli.recvline(timeout=2.0)
            print("[TEST][server] who:", who)
            cli.sendline(b"HI:" + who.rstrip(b"\n"))
            # Send some raw bytes to test recvn
            cli.send(b"XYZ123")
        finally:
            cli.close()

    t = threading.Thread(target=server_thread, daemon=True)
    t.start()

    try:
        print("[TEST] Connecting client...")
        c = remote("127.0.0.1", server.lport, timeout=3.0)
        try:
            wl = c.recvline(timeout=2.0)
            print("[TEST] welcome:", wl)
            assert wl == b"WELCOME\n"
            c.sendline(b"name=alice")
            # Be explicit: the server sends 'Your name?\n', so match full line
            c.recvuntil(b"Your name?\n", timeout=2.0)
            c.sendline(b"alice")
            reply = c.recvline(timeout=2.0)
            print("[TEST] reply:", reply)
            assert reply == b"HI:alice\n"
            # Now confirm recvn gets exact bytes
            part1 = c.recvn(3, timeout=2.0)
            part2 = c.recvn(3, timeout=2.0)
            print("[TEST] chunks:", part1, part2)
            assert part1 == b"XYZ"
            assert part2 == b"123"
            # check observability
            st = c.stats()
            print("[TEST] stats:")
            pprint.pprint(st)
            assert st["bytes_recv"] >= 1 and st["bytes_sent"] >= 1
            assert st["closed"] is False
            # test wiretap
            tap_file = os.path.join(os.path.dirname(__file__), "tap.bin")
            try:
                c.wiretap(tap_file)
                c.sendline(b"PING")
                # server won't reply, but tap should record outgoing
                time.sleep(0.1)
            finally:
                if os.path.exists(tap_file):
                    os.remove(tap_file)
        finally:
            c.close()
    finally:
        server.close()


if __name__ == "__main__":
    # Basic runner without pytest
    ok = True
    try:
        test_process_echo_basic()
        print("[OK] process tests")
    except Exception as e:
        ok = False
        print("[FAIL] process tests:", e)
    try:
        test_remote_listen_roundtrip()
        print("[OK] remote/listen tests")
    except Exception as e:
        ok = False
        print("[FAIL] remote/listen tests:", e)
    sys.exit(0 if ok else 1)
