#!/usr/bin/env python3
"""Simplified pwntools-like tubes for Sage environments."""

from __future__ import annotations

import os
import select
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
import ssl as _ssl
from typing import Any, Dict, Iterable, Iterator, Optional, Sequence, Tuple, Union
import pty
import fcntl
import termios
import re


__all__ = [
    "context",
    "remote",
    "tls",
    "process",
    "listen",
    "pwn",
    "PTY",
    "ssh",
    "SSH",
    "args",
]


_ByteLike = Union[bytes, bytearray, memoryview]


# Sentinel to request a pseudo-terminal for a stream
class _PTY:
    pass


PTY = _PTY()


class _Context:
    """Small subset of pwntools.context required for IO work."""

    _defaults: Dict[str, Any] = {
        "log_level": "info",
        "timeout": 30.0,
        "newline": b"\n",
        "encoding": "utf-8",
        # observability controls
        "log_timestamps": False,
        "log_preview": 160,
        "log_hex": False,
        "log_color": False,
        "log_strip_ansi": False,
        # 'auto' -> text if mostly printable, else hex; 'text' -> always text lines; 'hex' -> always hexdump
        "log_dump": "auto",
        # where to write logs: 'stderr' or 'stdout'
        "log_stream": "stderr",
        # optional log file path (append)
        "log_file": None,
        # interactive logging mode: 'off' | 'tags' | 'full'
        "interactive_log": "tags",
        # optional global wiretap sink for all tubes (file path or binary file-like)
        "wiretap": None,
        # strict delimiter handling for send*after
        "consume_delim_newline": False,
        # compatibility toggles
        "aslr": True,
        "noptrace": False,
        "randomize": False,
        "noterm": False,
        "local_libcdb": None,
    }

    def __init__(self) -> None:
        self._state = dict(self._defaults)
        self._stack: list[Dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> "_Context":
        self._state.update(kwargs)
        if "log_level" in kwargs:
            self._apply_debug_defaults()
        return self

    def __getattr__(self, name: str) -> Any:
        if name in self._state:
            return self._state[name]
        raise AttributeError(name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_"):
            super().__setattr__(name, value)
        else:
            self._state[name] = value
            if name == "log_level":
                self._apply_debug_defaults()

    def clear(self) -> None:
        self._state = dict(self._defaults)
        # do not auto-apply here; only when user sets log_level

    # When user switches to debug, default to hex dump + colored tags unless overridden
    def _apply_debug_defaults(self) -> None:
        try:
            level = str(self._state.get("log_level", "")).lower()
        except Exception:
            level = ""
        if level == "debug":
            # Only set if still at defaults
            if self._state.get("log_dump", "auto") == "auto":
                self._state["log_dump"] = "hex"
            if self._state.get("log_color", False) is False:
                self._state["log_color"] = True
            # In debug, prefer full logs inside interactive loop (while preserving user overrides)
            if self._state.get("interactive_log", "tags") == "tags":
                self._state["interactive_log"] = "full"

    @contextmanager
    def local(self, **kwargs: Any) -> Iterator["_Context"]:
        previous = dict(self._state)
        self._stack.append(previous)
        self._state.update(kwargs)
        try:
            yield self
        finally:
            self._state = self._stack.pop()


context = _Context()


_LEVELS = {
    "debug": 10,
    "info": 20,
    "warning": 30,
    "error": 40,
}


def _should_log(level: str) -> bool:
    return _LEVELS.get(level, 20) >= _LEVELS.get(context.log_level, 20)


def _to_hex(data: bytes, width: int = 16) -> str:
    # simple single-line hex preview
    return data.hex()


def _format_bytes(data: bytes) -> str:
    limit = int(context.log_preview or 160)
    if len(data) > limit:
        data = data[: limit - 3] + b"..."
    if context.log_hex:
        return _to_hex(data)
    preview = data.replace(b"\r", b"\\r").replace(b"\n", b"\\n")
    return preview.decode(context.encoding, errors="replace")


_COLOR = {
    "info": "\033[94m",
    "debug": "\033[92m",
    "warning": "\033[93m",
    "error": "\033[91m",
    "input": "\033[95m",
    "output": "\033[96m",
    "reset": "\033[0m",
}


def _maybe_color(s: str, role: str) -> str:
    if not getattr(context, "log_color", False):
        return s
    try:
        color = _COLOR.get(role, "")
        reset = _COLOR["reset"]
        return f"{color}{s}{reset}" if color else s
    except Exception:
        return s


_TAG_ROLE = {
    "IN": "input",
    "OUT": "output",
    "Switched": "warning",
}


def _format_tag(tag: str, role: str) -> str:
    # Only color the [TAG] token, not the entire line
    token = f"[{tag}]"
    return _maybe_color(token, role)


def _emit(line: str) -> None:
    stream = sys.stderr if getattr(context, "log_stream", "stderr") == "stderr" else sys.stdout
    print(line, file=stream)
    # also to log file if configured
    lf = getattr(context, "log_file", None)
    if lf:
        try:
            with open(lf, "a", encoding="utf-8", errors="replace") as fp:
                fp.write(line + "\n")
        except Exception:
            pass


def _log_tags(level: str, extra_tags: Optional[Sequence[str]], message: str) -> None:
    if not _should_log(level):
        return
    parts = []
    if context.log_timestamps:
        parts.append(f"[{time.strftime('%H:%M:%S')}]")
    parts.append(_format_tag(level.upper(), level.lower()))
    if extra_tags:
        for t in extra_tags:
            parts.append(_format_tag(t, _TAG_ROLE.get(t, "info")))
    line = " ".join(parts) + (f" {message}" if message else "")
    _emit(line)


def _log(level: str, message: str) -> None:
    _log_tags(level, None, message)


def _stage(prefix: str, message: str, level: Optional[str] = None) -> None:
    # stage markers like pwntools: [x], [+], [*], [-]
    if level is None:
        if prefix.startswith("[-]"):
            level = "warning"
        else:
            level = "info"
    _log(level, f"{prefix} {message}")


def _hexdump_block(data: bytes, start: int = 0, width: int = 16, group: int = 4) -> str:
    out_lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        # hex part grouped
        groups = [chunk[i : i + group] for i in range(0, len(chunk), group)]
        hex_groups = [" ".join(f"{b:02x}" for b in g) for g in groups]
        # pad last line to align ascii column
        pad_bytes = width - len(chunk)
        if pad_bytes:
            # each byte takes 2 + 1 space, plus one extra space between groups
            # easier: rebuild expected hex column width
            total_groups = (width + group - 1) // group
            hex_cols = []
            for gi in range(total_groups):
                base = gi * group
                sub = chunk[base : base + group]
                hx = " ".join(f"{b:02x}" for b in sub)
                hex_cols.append(hx.ljust(group * 3 - 1))  # 'xx ' * (group-1) + 'xx'
            hex_part = "  ".join(hex_cols)
        else:
            hex_part = "  ".join(hex_groups)
        # ascii part
        ascii_part = bytes((c if 32 <= c <= 126 else 0x2e) for c in chunk).decode("ascii")
        out_lines.append(f"{start + offset:08x}  {hex_part}  │{ascii_part}│")
    return "\n".join(out_lines)


def _debug_dump(label: str, data: bytes) -> None:
    if not _should_log("debug"):
        return
    tag = "IN" if label.lower().startswith("sent") else ("OUT" if label.lower().startswith("received") else None)
    if tag is None:
        _log("debug", f"{label} {len(data)} bytes:")
    else:
        _log_tags("debug", [tag], f"{label} {len(data)} bytes:")
    mode = str(getattr(context, "log_dump", "auto"))
    # Optionally strip ANSI to avoid noise from PTY-aware apps
    if getattr(context, "log_strip_ansi", False):
        data_to_show = re.sub(br"\x1b\[[0-9;?]*[a-zA-Z]", b"", data)
    else:
        data_to_show = data

    def mostly_printable(b: bytes) -> bool:
        if not b:
            return True
        printable = sum(1 for x in b if 32 <= x <= 126 or x in (9, 10, 13))
        return printable / max(1, len(b)) >= 0.8

    if mode == "text" or (mode == "auto" and mostly_printable(data_to_show) and len(data_to_show) <= 4096):
        # Render as escaped Python literal lines, not hexdump
        for line in data_to_show.splitlines(keepends=True):
            print("    " + repr(line))
    else:
        dump = _hexdump_block(data_to_show).replace("\n", "\n    ")
        print("    " + dump)


def _log_send(data: bytes, *, in_interactive: bool = False) -> None:
    # Optionally split tiny sends into per-byte logs
    split = bool(getattr(context, "debug_split_small_sends", False))
    if split and len(data) <= 16 and len(data) > 1 and _should_log("debug"):
        for b in data:
            _debug_dump("Sent", bytes([b]))
        return
    # During interactive mode, allow suppressing full dumps
    mode = str(getattr(context, "interactive_log", "tags"))
    if in_interactive and mode == "tags":
        _log_tags("debug", ["IN"], f"Sent {len(data)} bytes")
        return
    _debug_dump("Sent", data)


def _log_recv(data: bytes, *, in_interactive: bool = False) -> None:
    mode = str(getattr(context, "interactive_log", "tags"))
    if in_interactive and mode == "tags":
        _log_tags("debug", ["OUT"], f"Received {len(data)} bytes")
        return
    _debug_dump("Received", data)


def _ensure_bytes(data: Union[str, _ByteLike]) -> bytes:
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    if isinstance(data, str):
        return data.encode(context.encoding)
    raise TypeError(f"Unsupported type {type(data)!r}")


class Tube:
    """Common functionality shared by remote/process tubes."""

    def __init__(self, timeout: Optional[float] = None) -> None:
        self.timeout = context.timeout if timeout is None else timeout
        self._buffer = bytearray()
        self._closed = False
        # metrics
        now = time.monotonic()
        self._created_at = now
        self._last_send_at: Optional[float] = None
        self._last_recv_at: Optional[float] = None
        self._bytes_sent = 0
        self._bytes_recv = 0
        # optional per-tube wiretap sink (binary file-like with write())
        self._tap = None
        self._tap_owned = False
        # auto-enable global wiretap if configured
        try:
            global_tap = context.wiretap
            if global_tap:
                self.wiretap(global_tap)
        except Exception:
            pass
        # interactive state flag default
        self._in_interactive = False

    # -- hooks ---------------------------------------------------------
    def _fileno(self) -> int:
        raise NotImplementedError

    def _recv_raw(self, max_bytes: int) -> bytes:
        raise NotImplementedError

    def _send_raw(self, data: bytes) -> None:
        raise NotImplementedError

    def _close_raw(self) -> None:
        pass

    # -- context helpers ----------------------------------------------
    def __enter__(self) -> "Tube":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # -- state ---------------------------------------------------------
    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._close_raw()
            # close owned tap
            if self._tap is not None and getattr(self, "_tap_owned", False):
                try:
                    self._tap.close()
                except Exception:
                    pass
                finally:
                    self._tap = None
            _log("info", "Tube closed")

    def settimeout(self, timeout: Optional[float]) -> None:
        self.timeout = context.timeout if timeout is None else timeout

    # -- compatibility helpers --------------------------------------
    def shutdown(self, direction: str = "both") -> None:
        """Close one or both directions of the tube.

        direction: 'send' | 'recv' | 'both'
        """
        d = direction.lower()
        if d not in {"send", "recv", "both"}:
            raise ValueError("direction must be 'send', 'recv', or 'both'")
        try:
            if d in ("send", "both"):
                self._shutdown_send()
            if d in ("recv", "both"):
                self._shutdown_recv()
        except Exception:
            pass

    def _shutdown_send(self) -> None:
        # Overridden by subclasses if they can half-close
        self.close()

    def _shutdown_recv(self) -> None:
        # Overridden by subclasses if they can half-close
        self.close()

    def connected(self, direction: str = "any") -> bool:
        """Rudimentary connection state check.

        direction: 'send' | 'recv' | 'any'
        """
        if self._closed:
            return False
        d = direction.lower()
        if d in ("any", "recv") and self.can_recv(0.0):
            return True
        # If not readable, assume connected until proven otherwise
        return True

    def recvall(self, timeout: Optional[float] = None) -> bytes:
        """Read until closure or timeout.

        If timeout is provided, returns what has been received when it expires.
        """
        chunks: list[bytes] = []
        end_at = None if timeout is None else time.monotonic() + timeout
        while True:
            remaining = None if end_at is None else max(0.0, end_at - time.monotonic())
            data = self.recv(4096, timeout=remaining)
            if data:
                chunks.append(data)
                continue
            if self._closed:
                break
            if end_at is not None and time.monotonic() >= end_at:
                break
            # No data but not closed: brief pause to avoid busy loop
            break
        return b"".join(chunks)

    def wait_for_close(self, timeout: Optional[float] = None) -> Optional[int]:
        """Wait for the tube to close. Returns optional status code if known."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while not self._closed:
            if deadline is not None and time.monotonic() >= deadline:
                return None
            time.sleep(0.01)
        return None

    # -- buffering -----------------------------------------------------
    def can_recv(self, timeout: float = 0.0) -> bool:
        if self._buffer:
            return True
        if self._closed:
            return False
        fd = self._fileno()
        if fd < 0:
            return False
        ready, _, _ = select.select([fd], [], [], timeout)
        return bool(self._buffer) or bool(ready)

    def unrecv(self, data: Union[str, _ByteLike]) -> None:
        chunk = _ensure_bytes(data)
        self._buffer = bytearray(chunk) + self._buffer

    def _effective_timeout(self, timeout: Optional[float]) -> Optional[float]:
        if timeout is None:
            return self.timeout
        return timeout

    def _fill_buffer(self, required: int, timeout: Optional[float]) -> None:
        if self._closed or required <= 0:
            return

        eff_timeout = self._effective_timeout(timeout)
        # Treat 0.0 as non-blocking single poll: no deadline so we attempt a select(0)
        deadline = None if eff_timeout is None or eff_timeout == 0 else time.monotonic() + eff_timeout

        while len(self._buffer) < required and not self._closed:
            fd = self._fileno()
            if fd < 0:
                break

            wait_time: Optional[float]
            if deadline is None:
                wait_time = eff_timeout
            else:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                wait_time = remaining

            ready, _, _ = select.select([fd], [], [], wait_time)
            if not ready:
                # Non-blocking poll or zero timeout: return immediately
                if wait_time == 0:
                    break
                # select timed out without data; loop will re-check deadline
                continue

            chunk = self._recv_raw(4096)
            if not chunk:
                self._closed = True
                break
            self._buffer.extend(chunk)
            self._bytes_recv += len(chunk)
            self._last_recv_at = time.monotonic()
            _log_recv(chunk, in_interactive=self._in_interactive)
            # mirror to wiretap as incoming
            if self._tap is not None:
                try:
                    self._tap.write(b"< " + chunk)
                    if hasattr(self._tap, "flush"):
                        self._tap.flush()
                except Exception:
                    pass

    # -- recv/send -----------------------------------------------------
    def recv(self, numb: int = 4096, timeout: Optional[float] = None) -> bytes:
        if numb <= 0:
            return b""
        if not self._buffer:
            self._fill_buffer(1, timeout)
        if not self._buffer:
            return b""
        take = min(numb, len(self._buffer))
        data = bytes(self._buffer[:take])
        del self._buffer[:take]
        return data

    def recvn(self, numb: int, timeout: Optional[float] = None) -> bytes:
        target = numb
        eff_timeout = self._effective_timeout(timeout)
        deadline = None if eff_timeout is None else time.monotonic() + eff_timeout
        while len(self._buffer) < target and not self._closed:
            remaining = None
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return b""
            self._fill_buffer(len(self._buffer) + 1, remaining)
            if deadline is not None:
                if time.monotonic() >= deadline:
                    return b""
        if len(self._buffer) < target:
            if self._closed:
                raise EOFError("Connection closed")
            return b""
        data = bytes(self._buffer[:target])
        del self._buffer[:target]
        return data

    def recvuntil(
        self,
        delims: Union[str, _ByteLike, Sequence[Union[str, _ByteLike]]],
        *,
        drop: bool = False,
        timeout: Optional[float] = None,
    ) -> bytes:
        if isinstance(delims, (list, tuple)):
            targets = [_ensure_bytes(d) for d in delims]
        else:
            targets = [_ensure_bytes(delims)]
        if any(len(t) == 0 for t in targets):
            raise ValueError("Delimiter must not be empty")

        eff_timeout = self._effective_timeout(timeout)
        deadline = None if eff_timeout is None else time.monotonic() + eff_timeout

        while True:
            for delim in targets:
                idx = self._buffer.find(delim)
                if idx != -1:
                    end = idx + len(delim)
                    data = bytes(self._buffer[:end])
                    del self._buffer[:end]
                    if drop:
                        data = data[:-len(delim)]
                    return data
            if self._closed:
                raise EOFError("Connection closed before delimiter")
            if deadline is not None and time.monotonic() >= deadline:
                return b""
            remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
            self._fill_buffer(len(self._buffer) + 1, remaining)

    def recvline(
        self,
        *,
        timeout: Optional[float] = None,
        keepends: bool = True,
    ) -> bytes:
        data = self.recvuntil(context.newline, timeout=timeout)
        if not keepends and data.endswith(context.newline):
            data = data[:-len(context.newline)]
        return data

    def recvline_contains(
        self,
        keyword: Union[str, _ByteLike, Iterable[Union[str, _ByteLike]]],
        *,
        timeout: Optional[float] = None,
    ) -> bytes:
        if isinstance(keyword, (list, tuple, set)):
            needles = [_ensure_bytes(k) for k in keyword]
        else:
            needles = [_ensure_bytes(keyword)]
        eff_timeout = self._effective_timeout(timeout)
        deadline = None if eff_timeout is None else time.monotonic() + eff_timeout
        while True:
            if deadline is not None and time.monotonic() >= deadline:
                return b""
            remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
            line = self.recvline(timeout=remaining)
            if not line:  # 连接关闭或超时
                return b""
            for needle in needles:
                if needle in line:
                    return line

    def recvrepeat(self, timeout: Optional[float] = None) -> bytes:
        eff_timeout = self._effective_timeout(timeout)
        deadline = None if eff_timeout is None else time.monotonic() + eff_timeout
        chunks = []
        while True:
            data = self.recv(4096, timeout=eff_timeout)
            if data:
                chunks.append(data)
                continue
            if deadline is not None and time.monotonic() >= deadline:
                break
            if self._closed:
                break
            # 没有数据但未超时且未关闭时也应退出
            break
        return b"".join(chunks)

    def recvlines(
        self,
        numlines: int,
        *,
        timeout: Optional[float] = None,
        drop: bool = True,
    ) -> list[bytes]:
        result: list[bytes] = []
        for _ in range(numlines):
            line = self.recvline(timeout=timeout)
            if not line:
                break
            if drop:
                line = line.rstrip(context.newline)
            result.append(line)
        return result

    def clean(self, timeout: float = 0.05) -> bytes:
        data = bytearray()
        while True:
            chunk = self.recv(4096, timeout=timeout)
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    def send(self, data: Union[str, _ByteLike]) -> None:
        payload = _ensure_bytes(data)
        if self._closed:
            raise EOFError("Tube is closed")
        self._send_raw(payload)
        self._bytes_sent += len(payload)
        self._last_send_at = time.monotonic()
        _log_send(payload, in_interactive=self._in_interactive)
        # mirror to wiretap as outgoing
        if self._tap is not None:
            try:
                self._tap.write(b"> " + payload)
                if hasattr(self._tap, "flush"):
                    self._tap.flush()
            except Exception:
                pass

    def sendline(self, data: Union[str, _ByteLike]) -> None:
        payload = _ensure_bytes(data)
        if not payload.endswith(context.newline):
            payload += context.newline
        self.send(payload)

    # -- observability helpers ---------------------------------------
    def stats(self) -> Dict[str, Any]:
        return {
            "bytes_sent": self._bytes_sent,
            "bytes_recv": self._bytes_recv,
            "buffered": len(self._buffer),
            "created_at": self._created_at,
            "last_send_at": self._last_send_at,
            "last_recv_at": self._last_recv_at,
            "closed": self._closed,
        }

    def reset_stats(self) -> None:
        self._bytes_sent = 0
        self._bytes_recv = 0
        self._last_send_at = None
        self._last_recv_at = None

    def peek(self, n: Optional[int] = None) -> bytes:
        if n is None:
            return bytes(self._buffer)
        return bytes(self._buffer[: max(0, n)])

    def wiretap(self, sink: Union[str, Any]) -> None:
        """Mirror raw IO to a sink (file path or binary file-like)."""
        if isinstance(sink, (str, bytes, os.PathLike)):
            self._tap = open(sink, "ab")
            self._tap_owned = True
        else:
            self._tap = sink
            self._tap_owned = False

    def sendafter(
        self,
        delim: Union[str, _ByteLike],
        data: Union[str, _ByteLike],
        *,
        timeout: Optional[float] = None,
    ) -> bytes:
        d = _ensure_bytes(delim)
        received = self.recvuntil(d, timeout=timeout)
        if getattr(context, "consume_delim_newline", False):
            if self._buffer.startswith(context.newline):
                del self._buffer[: len(context.newline)]
        self.send(data)
        return received

    def sendlineafter(
        self,
        delim: Union[str, _ByteLike],
        data: Union[str, _ByteLike],
        *,
        timeout: Optional[float] = None,
    ) -> bytes:
        d = _ensure_bytes(delim)
        received = self.recvuntil(d, timeout=timeout)
        if getattr(context, "consume_delim_newline", False):
            if self._buffer.startswith(context.newline):
                del self._buffer[: len(context.newline)]
        self.sendline(data)
        return received

    def sendthen(
        self,
        delim: Union[str, _ByteLike],
        data: Union[str, _ByteLike],
        *,
        timeout: Optional[float] = None,
    ) -> bytes:
        self.send(data)
        return self.recvuntil(delim, timeout=timeout)

    def sendlinethen(
        self,
        delim: Union[str, _ByteLike],
        data: Union[str, _ByteLike],
        *,
        timeout: Optional[float] = None,
    ) -> bytes:
        self.sendline(data)
        return self.recvuntil(delim, timeout=timeout)

    def interactive(self) -> None:
        if self._closed:
            raise EOFError("Tube is closed")
        _log_tags("info", ["Switched"], "to interactive mode")
        stdin_fd = sys.stdin.fileno()
        stdout = sys.stdout.buffer

        try:
            self._in_interactive = True
            while True:
                fds = [self._fileno(), stdin_fd]
                ready, _, _ = select.select(fds, [], [], 0.1)
                if self._fileno() in ready:
                    data = self.recv(4096, timeout=0.0)
                    if data:
                        stdout.write(data)
                        stdout.flush()
                    elif self._closed:
                        break
                if stdin_fd in ready:
                    user_input = os.read(stdin_fd, 4096)
                    if not user_input:
                        break
                    self.send(user_input)
        except KeyboardInterrupt:
            _log("info", "Interactive session interrupted")
        finally:
            self._in_interactive = False
            self.close()


class _SocketTubeBase(Tube):
    """Common socket-backed tube implementation."""

    def __init__(self, sock: socket.socket, timeout: Optional[float]) -> None:
        self._sock = sock
        super().__init__(timeout)
        self._sock.setblocking(False)

    def _fileno(self) -> int:
        return self._sock.fileno()

    def _recv_raw(self, max_bytes: int) -> bytes:
        try:
            return self._sock.recv(max_bytes)
        except (BlockingIOError, _ssl.SSLWantReadError, _ssl.SSLWantWriteError):
            return b""

    def _send_raw(self, data: bytes) -> None:
        view = memoryview(data)
        total = 0
        while total < len(data):
            try:
                sent = self._sock.send(view[total:])
            except (BlockingIOError, _ssl.SSLWantReadError, _ssl.SSLWantWriteError):
                select.select([], [self._sock], [], self.timeout)
                continue
            if sent == 0:
                raise EOFError("Remote closed the connection")
            total += sent

    def _close_raw(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._sock.close()

    def _shutdown_send(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def _shutdown_recv(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RD)
        except OSError:
            pass


def _map_family(fam: Union[str, int]) -> int:
    if isinstance(fam, int):
        return fam
    fam_l = str(fam).lower()
    if fam_l in ("any", "unspec"):
        return socket.AF_UNSPEC
    if fam_l in ("ipv4", "inet"):
        return socket.AF_INET
    if fam_l in ("ipv6", "inet6"):
        return socket.AF_INET6
    return socket.AF_UNSPEC


class remote(_SocketTubeBase):
    """TCP tube mirroring pwntools.remote basics."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        timeout: Optional[float] = None,
        fam: Union[str, int] = "any",
        typ: Union[str, int] = "tcp",
        sock: Optional[socket.socket] = None,
        ssl: bool = False,
        ssl_context: Optional[_ssl.SSLContext] = None,
        ssl_args: Optional[Dict[str, Any]] = None,
        sni: Union[str, bool] = True,
    ) -> None:
        if isinstance(typ, str) and typ.lower() != "tcp":
            raise NotImplementedError("Only TCP is supported currently")

        if sock is not None:
            # wrap existing socket
            self._peer = None
            super().__init__(sock, timeout)
            _stage("[+]", f"Opened connection to {host}:{port} (from socket)")
            return

        err: Optional[BaseException] = None
        created: Optional[socket.socket] = None
        sockaddr: Optional[Tuple[str, int]] = None

        family = _map_family(fam)
        try:
            addrinfo = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise OSError(f"Failed to resolve {host}:{port} - {exc}") from exc

        _stage("[x]", f"Opening {'TLS ' if ssl else ''}connection to {host} on port {port}")
        for af, socktype, proto, _, candidate_addr in addrinfo:
            candidate = None
            try:
                candidate = socket.socket(af, socktype, proto)
                if timeout is not None:
                    candidate.settimeout(timeout)
                candidate.connect(candidate_addr)
                candidate.settimeout(None)
                if ssl:
                    ctx = ssl_context or _ssl.create_default_context()
                    server_hostname: Optional[str]
                    if sni is True:
                        server_hostname = host
                    elif sni is False:
                        server_hostname = None
                    else:
                        server_hostname = str(sni)
                    kw: Dict[str, Any] = {}
                    if ssl_args:
                        kw.update(ssl_args)
                    candidate = ctx.wrap_socket(candidate, server_hostname=server_hostname, **kw)
                created = candidate
                sockaddr = candidate_addr
                break
            except OSError as exc:
                err = exc
                if candidate is not None:
                    candidate.close()
                continue

        if created is None or sockaddr is None:
            if err is not None:
                raise err
            raise OSError("Failed to connect to remote host")

        self._peer = sockaddr
        super().__init__(created, timeout)
        _stage("[+]", f"Opened {'TLS ' if ssl else ''}connection to {host} on port {port}")

    @classmethod
    def fromsocket(cls, sock: socket.socket, timeout: Optional[float] = None) -> "remote":
        inst = object.__new__(cls)
        _SocketTubeBase.__init__(inst, sock, timeout)
        inst._peer = None
        return inst


def tls(host: str, port: int, **kwargs: Any) -> remote:
    """Convenience wrapper for TLS connections.

    Example: s = tls('example.com', 443)
    """
    kwargs.setdefault("ssl", True)
    return remote(host, port, **kwargs)


class process(Tube):
    """Spawn a local process and expose tube interface."""

    def __init__(
        self,
        argv: Union[str, Sequence[str]],
        *,
        timeout: Optional[float] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        shell: Optional[bool] = None,
        executable: Optional[str] = None,
        stdin: Any = subprocess.PIPE,
        stdout: Any = subprocess.PIPE,
        stderr: Any = subprocess.STDOUT,
        close_fds: bool = True,
        preexec_fn: Optional[Any] = None,
        alarm: Optional[int] = None,
        tty: Optional[bool] = None,
        **_: Any,
    ) -> None:
        super().__init__(timeout)
        use_shell = isinstance(argv, str) if shell is None else bool(shell)
        argv_display = argv if isinstance(argv, str) else " ".join(map(str, argv))
        _stage("[x]", f"Starting local process '{argv_display}'")
        self._use_pty = False
        self._master_fd: Optional[int] = None

        # PTY decision: explicit tty=True or any stream is PTY sentinel
        want_tty = bool(tty) or (stdin is PTY) or (stdout is PTY) or (stderr is PTY)

        if want_tty:
            self._use_pty = True
            master_fd, slave_fd = pty.openpty()
            # Child should get the slave as 0/1/2
            def _child_setup():
                try:
                    os.setsid()
                except Exception:
                    pass
                # set controlling TTY if available
                try:
                    fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
                except Exception:
                    pass

            self._proc = subprocess.Popen(
                argv,
                shell=use_shell,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                cwd=cwd,
                env=env,
                bufsize=0,
                executable=executable,
                close_fds=close_fds,
                preexec_fn=_child_setup if preexec_fn is None else preexec_fn,
            )
            # Parent: close slave, keep master non-blocking
            try:
                os.close(slave_fd)
            except Exception:
                pass
            self._master_fd = master_fd
            os.set_blocking(master_fd, False)
            self._stdout_fd = master_fd
            # no separate stdin pipe; we will write to master directly
            self._stdin = None
        else:
            self._proc = subprocess.Popen(
                argv,
                shell=use_shell,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                cwd=cwd,
                env=env,
                bufsize=0,
                executable=executable,
                close_fds=close_fds,
                preexec_fn=preexec_fn,
            )
            if self._proc.stdout is None or self._proc.stdin is None:
                raise RuntimeError("Failed to create pipes")
            self._stdout_fd = self._proc.stdout.fileno()
            os.set_blocking(self._stdout_fd, False)
            self._stdin = self._proc.stdin
        _stage("[+]", f"Starting local process '{argv_display}' : pid {self._proc.pid}")

    def _fileno(self) -> int:
        return self._stdout_fd

    def _recv_raw(self, max_bytes: int) -> bytes:
        try:
            return os.read(self._stdout_fd, max_bytes)
        except BlockingIOError:
            return b""
        except OSError:
            self._closed = True
            return b""

    def _send_raw(self, data: bytes) -> None:
        if self._use_pty and self._master_fd is not None:
            # Write directly to PTY master
            total = 0
            view = memoryview(data)
            while total < len(data):
                try:
                    n = os.write(self._master_fd, view[total:])
                except BlockingIOError:
                    select.select([], [self._master_fd], [], self.timeout)
                    continue
                if n == 0:
                    raise EOFError("pty closed")
                total += n
            return
        # pipe mode
        if self._stdin is None or self._stdin.closed:
            raise EOFError("stdin closed")
        self._stdin.write(data)
        self._stdin.flush()

    def poll(self) -> Optional[int]:
        return self._proc.poll()

    def wait(self, timeout: Optional[float] = None) -> Optional[int]:
        try:
            return self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def kill(self) -> None:
        self._proc.kill()

    # passthrough commonly used fields
    def __getattr__(self, name: str) -> Any:
        if name in {"pid", "stdin", "stdout", "stderr", "returncode"}:
            return getattr(self._proc, name)
        raise AttributeError(name)

    def _close_raw(self) -> None:
        try:
            self._stdin.close()
        except Exception:
            pass
        try:
            self._proc.terminate()
        except Exception:
            pass
        try:
            self._proc.wait(timeout=1)
        except Exception:
            pass


def _map_bindaddr_family(bindaddr: str, fam: Union[str, int]) -> int:
    if isinstance(fam, int):
        return fam
    fam_l = str(fam).lower()
    if fam_l in ("ipv6", "inet6") or ":" in bindaddr:
        return socket.AF_INET6
    if fam_l in ("ipv4", "inet"):
        return socket.AF_INET
    return socket.AF_INET


class listen:
    """Minimal listener compatible with pwntools.listen for testing."""

    def __init__(self, host: str = "0.0.0.0", port: int = 0, backlog: int = 128, *, fam: Union[str, int] = "any", typ: Union[str, int] = "tcp") -> None:
        af = _map_bindaddr_family(host, fam)
        self.family = af
        self._sock = socket.socket(af, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if af == socket.AF_INET6:
            self._sock.bind((host, port, 0, 0))
        else:
            self._sock.bind((host, port))
        self._sock.listen(backlog)
        sockname = self._sock.getsockname()
        if af == socket.AF_INET6:
            self.lhost, self.lport = sockname[0], sockname[1]
        else:
            self.lhost, self.lport = sockname
        _stage("[*]", f"Listening on {self.lhost}:{self.lport}")

    def wait_for_connection(self, timeout: Optional[float] = None) -> remote:
        self._sock.settimeout(timeout)
        conn, addr = self._sock.accept()
        tube = _SocketTube(conn)
        _log("info", f"Accepted connection from {addr[0]}:{addr[1]}")
        return tube

    def close(self) -> None:
        self._sock.close()


class _SocketTube(_SocketTubeBase):
    """Internal socket tube for accepted connections."""
    def __init__(self, sock: socket.socket, timeout: Optional[float] = None) -> None:
        super().__init__(sock, timeout)

# expose module alias so `from pwn import *; pwn.process(...)` works
pwn = sys.modules[__name__]


class SSH:
    """Lightweight SSH session compatible with common pwntools usage.

    Uses the local `ssh` client for portability. This provides a close
    approximation to pwnlib.tubes.ssh for interactive work and running
    commands, without requiring extra dependencies.
    """

    def __init__(
        self,
        *,
        user: Optional[str] = None,
        host: Optional[str] = None,
        port: int = 22,
        password: Optional[str] = None,  # not supported with system ssh
        key: Optional[str] = None,       # private key text (unsupported)
        keyfile: Optional[str] = None,
        proxy_command: Optional[str] = None,
        proxy_sock: Optional[str] = None,
        level: Optional[str] = None,
        cache: bool = True,
        ssh_agent: bool = True,
        ignore_config: bool = False,
        raw: bool = False,
        auth_none: bool = False,
        timeout: Optional[float] = None,
        **_: Any,
    ) -> None:
        self.user = user
        self.host = host
        self.port = port
        self.keyfile = os.path.expanduser(keyfile) if keyfile else None
        self.timeout = timeout
        self.proxy_command = proxy_command
        self.ignore_config = ignore_config
        self.ssh_agent = ssh_agent
        self._closed = False

        if self.host is None:
            raise ValueError("host is required")

        self.target = f"{self.user}@{self.host}" if self.user else self.host
        self._base = ["ssh"]
        # Keep TTY-friendly defaults
        if self.port:
            self._base += ["-p", str(self.port)]
        if self.keyfile:
            self._base += ["-i", self.keyfile]
        if self.ignore_config:
            self._base += ["-F", "/dev/null"]
        if not self.ssh_agent:
            self._base += ["-o", "IdentitiesOnly=yes"]
        if self.proxy_command:
            self._base += ["-o", f"ProxyCommand={self.proxy_command}"]
        # Safer defaults
        self._base += [
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=4",
        ]

    # -- helpers -----------------------------------------------------
    def _argv(self, extra: Sequence[str]) -> list[str]:
        return list(self._base) + list(extra) + [self.target]

    def _run_bytes(self, cmd: Union[str, Sequence[Union[str, bytes]]]) -> bytes:
        if isinstance(cmd, (list, tuple)):
            remote_cmd = " ".join(map(lambda x: x.decode() if isinstance(x, (bytes, bytearray)) else str(x), cmd))
        else:
            remote_cmd = str(cmd)
        argv = self._argv(["--", remote_cmd])
        p = process(argv, tty=False, timeout=self.timeout)
        out = p.recvrepeat(1.0)
        p.close()
        return out

    # -- pwntools-like conveniences --------------------------------
    def __call__(self, cmd: Union[str, Sequence[Union[str, bytes]]]) -> bytes:
        return self._run_bytes(cmd)

    def __getitem__(self, cmd: Union[str, bytes]) -> bytes:
        return self._run_bytes(cmd)

    def __getattr__(self, name: str):
        # s.echo('hello') -> run 'echo hello'
        def runner(*args: Union[str, bytes, int]) -> bytes:
            parts: list[str] = [name]
            for a in args:
                if isinstance(a, bytes):
                    parts.append(a.decode())
                else:
                    parts.append(str(a))
            return self._run_bytes(parts)
        return runner

    # -- connection management --------------------------------------
    def close(self) -> None:
        self._closed = True

    def connected(self) -> bool:
        return not self._closed

    # -- higher level helpers ---------------------------------------
    def shell(self, shell: Optional[str] = None, tty: bool = True) -> process:
        argv = list(self._base)
        if tty:
            argv.append("-tt")
        argv.append(self.target)
        if shell is not None:
            argv += ["--", shell]
        return process(argv, tty=tty, timeout=self.timeout)

    def system(self, cmd: Union[str, Sequence[str]], tty: bool = True, cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> process:
        # run a remote command and attach as Tube
        if isinstance(cmd, (list, tuple)):
            remote_cmd = " ".join(map(str, cmd))
        else:
            remote_cmd = str(cmd)
        argv = list(self._base)
        if tty:
            argv.append("-tt")
        argv += [self.target, "--", remote_cmd]
        return process(argv, tty=tty, timeout=self.timeout, cwd=cwd, env=env)

    def process(self, argv: Union[str, Sequence[str]], tty: bool = True, cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> process:
        # alias of system with argv
        return self.system(argv, tty=tty, cwd=cwd, env=env)

    def remote(self, host: str, port: int, timeout: Optional[float] = None) -> process:
        # Create a direct TCP connection through SSH stdio
        argv = list(self._base) + ["-W", f"{host}:{port}", self.target]
        return process(argv, tty=False, timeout=timeout or self.timeout)

    # simple file helpers via cat / dd
    def download_data(self, remote: str) -> bytes:
        return self._run_bytes(["cat", remote])

    def upload_data(self, data: Union[bytes, str], remote: str) -> None:
        if isinstance(data, str):
            data = data.encode()
        # Use: ssh target 'cat > remote'
        argv = self._argv(["--", f"cat > {remote}"])
        p = process(argv, tty=False, timeout=self.timeout)
        p.send(data)
        p.close()


def ssh(*, user: Optional[str] = None, host: Optional[str] = None, port: int = 22, password: Optional[str] = None, key: Optional[str] = None, keyfile: Optional[str] = None, proxy_command: Optional[str] = None, proxy_sock: Optional[str] = None, level: Optional[str] = None, cache: bool = True, ssh_agent: bool = True, ignore_config: bool = False, raw: bool = False, auth_none: bool = False, timeout: Optional[float] = None, **kw: Any) -> SSH:
    """Create an SSH session approximating pwnlib.tubes.ssh.ssh.

    Minimal subset implemented via system ssh, no extra deps.
    """
    return SSH(user=user, host=host, port=port, password=password, key=key, keyfile=keyfile, proxy_command=proxy_command, proxy_sock=proxy_sock, level=level, cache=cache, ssh_agent=ssh_agent, ignore_config=ignore_config, raw=raw, auth_none=auth_none, timeout=timeout, **kw)
# -- args compatibility ----------------------------------------------
class _Args:
    """Minimal pwntools-like args parser.

    - Parses env vars with prefix PWNLIB_ and command-line tokens of the form KEY or KEY=VAL
    - Exposes mapping-like and attribute-like access; missing keys -> '' (empty string)
    - Applies common magic keys to context (DEBUG/SILENT/LOG_LEVEL/LOG_FILE/TIMEOUT/STDERR/NOASLR/NOPTRACE/NOTERM)
    """

    def __init__(self) -> None:
        self._store: Dict[str, str] = {}
        self._parsed = False
        self._parse()

    def _parse(self) -> None:
        if self._parsed:
            return
        self._parsed = True
        # 1) Env vars PWNLIB_*
        for k, v in os.environ.items():
            if k.startswith("PWNLIB_"):
                key = k[len("PWNLIB_"):]
                self._store[key] = v
        # 2) CLI tokens like KEY or KEY=VAL; remove them from sys.argv
        keep: list[str] = [sys.argv[0]]
        for tok in sys.argv[1:]:
            if "=" in tok:
                k, _, v = tok.partition("=")
                if k and k.isidentifier():
                    self._store[k] = v
                    continue
            if tok.isidentifier():
                self._store[tok] = "1"
                continue
            keep.append(tok)
        sys.argv[:] = keep
        # 3) Apply common magic
        self._apply_magic()

    def _asbool(self, s: str) -> bool:
        return s.lower() in {"1", "true", "yes", "on"}

    def _apply_magic(self) -> None:
        s = self._store
        if s.get("DEBUG"):
            context.log_level = "debug"  # triggers debug defaults
        if s.get("SILENT"):
            context.log_level = "error"
        if "LOG_LEVEL" in s:
            context.log_level = s["LOG_LEVEL"].lower()
        if "LOG_FILE" in s:
            context.log_file = s["LOG_FILE"]
        if s.get("STDERR"):
            context.log_stream = "stderr"
        if "TIMEOUT" in s:
            try:
                context.timeout = float(s["TIMEOUT"])  # type: ignore
            except Exception:
                pass
        if s.get("NOASLR"):
            context.aslr = False
        if s.get("NOPTRACE"):
            context.noptrace = True
        if s.get("NOTERM"):
            context.noterm = True
        if "LOCAL_LIBCDB" in s:
            context.local_libcdb = s["LOCAL_LIBCDB"]

    # mapping-like
    def __getitem__(self, k: str) -> str:
        return self._store.get(k, "")

    def get(self, k: str, default: str = "") -> str:
        return self._store.get(k, default)

    # attribute-like
    def __getattr__(self, k: str) -> str:
        if k in self._store:
            return self._store[k]
        return ""

    def __repr__(self) -> str:
        return f"_Args({self._store!r})"


args = _Args()
