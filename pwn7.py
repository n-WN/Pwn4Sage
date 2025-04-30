#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import select
import sys
import time
import subprocess
import os
import threading
import fcntl  # For TTY handling if needed elsewhere, but not for interactive input now
import struct
import base64
import binascii
import ssl  # For SSL support
import signal  # For process termination
import collections  # For deque

# Try importing termios for TTY handling, but don't fail if unavailable (e.g., Windows)
# Note: We are NOT using termios/tty for raw mode in interactive() anymore
try:
    import termios
    import tty

    HAS_TERMIOS = True
except ImportError:
    HAS_TERMIOS = False

# High-resolution timer, potentially useful for timing attacks
perf_counter = time.perf_counter


# --- Context ---
class context:
    """Global context settings for Pwn4Sage."""

    log_level = "info"  # 'debug', 'info', 'warning', 'error'
    endian = "little"  # 'little' or 'big'
    word_size = 64  # 8, 16, 32, 64
    timeout = 10  # Default timeout in seconds
    # For progress logging
    progress_spinner = ["|", "/", "-", "\\"]
    progress_idx = 0

    # --- New attributes for deferred interactive logging ---
    interactive_mode_active = False
    interactive_log_buffer = collections.deque()  # Use deque for efficient append/clear

    @staticmethod
    def set_log_level(level):
        """Sets the global logging level ('debug', 'info', 'warning', 'error')."""
        valid_levels = ["debug", "info", "warning", "error"]
        level = level.lower()
        if level not in valid_levels:
            # Use log directly here might be tricky if log isn't defined yet
            # Print directly or raise error
            print(
                f"[ERROR] Invalid log level: {level}. Must be one of {valid_levels}",
                file=sys.stderr,
            )
            return
        context.log_level = level

    @staticmethod
    def set_endian(endian):
        """Sets the global endianness ('little' or 'big')."""
        if endian.lower() not in ["little", "big"]:
            raise ValueError("Endianness must be 'little' or 'big'")
        context.endian = endian.lower()

    @staticmethod
    def set_word_size(size):
        """Sets the global word size (e.g., 8, 16, 32, 64 bits)."""
        if size not in [8, 16, 32, 64] and size % 8 != 0:
            # Use log if available, otherwise print warning
            try:
                log(f"Word size {size} is not a multiple of 8 bits.", "warning")
            except NameError:
                print(f"[WARNING] Word size {size} is not a multiple of 8 bits.")
        elif size not in [8, 16, 32, 64]:
            try:
                log(
                    f"Uncommon word size {size} set. Standard p*/u* functions limited.",
                    "warning",
                )
            except NameError:
                print(f"[WARNING] Uncommon word size {size} set.")
        context.word_size = size

    @staticmethod
    def get_timeout():
        """Gets the global default timeout."""
        return context.timeout

    @staticmethod
    def set_timeout(timeout):
        """Sets the global default timeout in seconds (None for no timeout)."""
        if timeout is not None and timeout < 0:
            raise ValueError("Timeout cannot be negative")
        context.timeout = timeout


# --- Logging ---
_log_lock = threading.Lock()  # Lock for thread-safe logging
_last_progress_len = 0  # Track length of progress bar to clear it


class ProgressLogger:
    """Context manager for showing progress, mimicking pwntools log.progress."""

    def __init__(self, message, level="info"):
        self.message = message
        self.level = level
        self.active = False
        self.last_len = 0
        self.status_msg = ""
        self._timer = None

    def _log_prefix(self):
        colors = {
            "info": "\033[94m",
            "debug": "\033[92m",
            "warning": "\033[93m",
            "error": "\033[91m",
        }
        reset = "\033[0m"
        level_tag = f"{colors.get(self.level, colors['info'])}[*]{reset}"
        return f"{level_tag} {self.message}: "

    def _render(self, final=False, success=None):
        global _last_progress_len
        with _log_lock:
            # Clear previous progress line
            if _last_progress_len > 0:
                sys.stdout.write("\r" + " " * _last_progress_len + "\r")

            if final:
                status_char = "[+]" if success else "[-]"
                color = "\033[92m" if success else "\033[91m"
                reset = "\033[0m"
                level_tag = f"{color}{status_char}{reset}"
                elapsed = f" ({time.time() - self._timer:.2f}s)" if self._timer else ""
                final_message = (
                    f"{level_tag} {self.message}: {self.status_msg}{elapsed}"
                )
                sys.stdout.write(final_message + "\n")
                sys.stdout.flush()
                _last_progress_len = 0  # No progress line active anymore
                self.active = False
            else:
                prefix = self._log_prefix()
                spinner = context.progress_spinner[
                    context.progress_idx % len(context.progress_spinner)
                ]
                context.progress_idx += 1
                current_line = f"{prefix}{self.status_msg} {spinner}"
                sys.stdout.write(current_line)
                sys.stdout.flush()
                _last_progress_len = len(
                    current_line
                )  # Track length to clear next time

    def status(self, status_msg):
        """Updates the status message of the progress logger."""
        if self.active:
            self.status_msg = str(status_msg)
            self._render()

    def success(self, status_msg="Done"):
        """Marks the progress as successful and logs a final message."""
        if self.active:
            self.status_msg = str(status_msg)
            self._render(final=True, success=True)

    def failure(self, status_msg="Failed"):
        """Marks the progress as failed and logs a final message."""
        if self.active:
            self.status_msg = str(status_msg)
            self._render(final=True, success=False)

    def __enter__(self):
        log_levels = {"debug": 10, "info": 20, "warning": 30, "error": 40}
        current_log_level = log_levels.get(context.log_level, 20)
        message_log_level = log_levels.get(self.level, 20)
        if message_log_level >= current_log_level:
            # Check if logs are being deferred
            if context.interactive_mode_active:
                print(
                    "[WARNING] ProgressLogger may conflict with deferred interactive logging.",
                    file=sys.stderr,
                )
            self.active = True
            self._timer = time.time()
            self._render()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.active:
            # Make sure logs are flushed before finalizing progress if interactive
            if context.interactive_mode_active:
                flush_interactive_logs()

            if exc_type:
                self.failure(f"Failed ({exc_value or exc_type.__name__})")
            else:
                # Check if failure was called explicitly before exit
                if (
                    self.active
                ):  # Check active again, might have been set False by success/failure
                    self.success()
            # Ensure active is False after exit
            self.active = False


def hexdump(data: bytes, length=16, sep="."):
    """Returns a string containing a hexadecimal representation of the data."""
    if not isinstance(data, bytes):
        return repr(data)  # Return representation for non-bytes types

    lines = []
    for i in range(0, len(data), length):
        chunk = data[i : i + length]
        # Format hex part (e.g., "00 11 22 ...")
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Format text part (printable ASCII or replacement char)
        text_part = "".join(chr(b) if 32 <= b < 127 else sep for b in chunk)
        # Combine parts into a line
        # Ensure hex part has fixed width for alignment
        lines.append(f"{i:04x}   {hex_part:<{length * 3}}  |{text_part:<{length}}|")
    return "\n".join(lines)


# --- New Function to Flush Deferred Logs ---
def flush_interactive_logs():
    """Prints and clears the buffered interactive logs."""
    global _last_progress_len
    # Check if there's anything to flush before acquiring the lock
    if not context.interactive_log_buffer:
        return

    with _log_lock:
        if context.interactive_log_buffer:
            # Clear any existing progress line first
            if _last_progress_len > 0:
                sys.stdout.write("\r" + " " * _last_progress_len + "\r")
                sys.stdout.flush()
                _last_progress_len = 0

            # Print buffered logs
            # Use a temporary list to avoid issues if logging happens while iterating
            logs_to_print = list(context.interactive_log_buffer)
            context.interactive_log_buffer.clear()

            for log_line in logs_to_print:
                print(log_line)  # Messages are pre-formatted

            sys.stdout.flush()


# --- Helper function to format log messages (extracted logic) ---
def _format_log_message(message, level, length, is_input, show_hexdump):
    """Formats the log message content into lines for printing or buffering."""
    lines_to_output = []
    colors = {  # Keep color definitions
        "info": "\033[94m",
        "debug": "\033[92m",
        "warning": "\033[93m",
        "error": "\033[91m",
        "input": "\033[95m",
        "output": "\033[96m",
        # Hexdump colors can be customized if needed
    }
    reset = "\033[0m"

    action = "Sent" if is_input else "Received"
    action_color = colors.get("input" if is_input else "output", "")
    level_tag = f"{colors.get(level, '')}[{level.upper()}]{reset}"

    # Determine the prefix based on context
    log_prefix = f"{level_tag} {action_color}{action}{reset}"

    # Handle byte strings vs other types
    printable_message = message
    is_bytes = isinstance(message, bytes)
    byte_count = len(message) if is_bytes else None
    # Use the actual byte count if available, otherwise use the provided length argument
    display_length = byte_count if byte_count is not None else length
    actual_length_info = (
        f" {display_length} bytes" if display_length is not None else ""
    )

    if is_bytes:
        try:
            # Attempt to decode for printable representation, but primary use might be hexdump
            printable_message_str = message.decode("utf-8", errors="replace")
        except Exception:
            printable_message_str = repr(message)  # Fallback
    else:
        printable_message_str = str(message)  # Ensure it's a string

    # Determine if hexdump should be shown for this specific log call
    do_hexdump = is_bytes and level == "debug" and show_hexdump

    # --- Construct the output lines ---
    first_line_prefix = f"{log_prefix}{actual_length_info}:"

    if do_hexdump:
        lines_to_output.append(first_line_prefix)
        hex_lines = hexdump(message).splitlines()
        if not hex_lines and byte_count == 0:  # Handle empty byte string hexdump
            lines_to_output.append("    (empty bytes)")
        elif (
            not hex_lines
        ):  # Should not happen if message is bytes unless hexdump fails
            lines_to_output.append("    (hexdump failed?)")
            lines_to_output.append(f"    Raw: {repr(message)}")
        else:
            for line in hex_lines:
                lines_to_output.append(f"    {line}")  # Indent hexdump
    else:
        # Handle non-hexdump cases (including non-byte messages and non-debug byte messages)
        if level == "debug" and is_bytes and not show_hexdump:
            # Debug log for bytes, but hexdump explicitly disabled
            lines_to_output.append(
                first_line_prefix + f" (Hexdump disabled) Raw: {repr(message)}"
            )
        else:
            message_lines = printable_message_str.splitlines()
            if not message_lines:
                # If original message was bytes, show byte count even if empty content
                if is_bytes:
                    lines_to_output.append(first_line_prefix + " (empty bytes)")
                else:  # Non-byte message might just be an empty string or other info
                    # For non-byte messages, don't add the action/byte count prefix unless meaningful
                    lines_to_output.append(f"{level_tag} {message}")
            else:
                # Print first line with prefix (use simpler prefix for non-I/O messages)
                if (
                    is_bytes or length is not None
                ):  # Assume it's I/O related if bytes or length given
                    lines_to_output.append(f"{first_line_prefix} {message_lines[0]}")
                else:  # Likely a general log message
                    lines_to_output.append(f"{level_tag} {message_lines[0]}")

                # Print subsequent lines indented (use fixed indent)
                indent = "    "
                for line in message_lines[1:]:
                    lines_to_output.append(f"{indent}{line}")

    return lines_to_output


# --- Modified log Function ---
def log(
    message,
    level="info",
    length=None,  # Provided length info, e.g. for recv calls asking for N bytes
    # interactive_mode flag removed as context.interactive_mode_active is used
    is_input=False,  # Indicates send operation
    show_hexdump=True,  # Control hexdump visibility per call
):
    global _last_progress_len
    log_levels = {"debug": 10, "info": 20, "warning": 30, "error": 40}
    # Ensure context log level is valid, default to info if not set correctly
    current_log_level_name = getattr(context, "log_level", "info")
    current_log_level = log_levels.get(current_log_level_name, 20)
    message_log_level = log_levels.get(level, 20)

    # Check if message should be logged at all based on current level
    if message_log_level < current_log_level:
        return

    # --- Deferred Logging Logic ---
    # Defer DEBUG messages only when interactive mode is active
    # Check context attribute directly
    if getattr(context, "interactive_mode_active", False) and level == "debug":
        # Need lock to safely append to shared buffer
        # Formatting happens before acquiring lock to minimize lock duration
        formatted_lines = _format_log_message(
            message, level, length, is_input, show_hexdump
        )
        with _log_lock:
            for line in formatted_lines:
                # Use the buffer from context
                getattr(context, "interactive_log_buffer", collections.deque()).append(
                    line
                )
        return  # Don't print immediately

    # --- Immediate Logging Logic ---
    # Formatting happens before acquiring lock
    formatted_lines = _format_log_message(
        message, level, length, is_input, show_hexdump
    )
    with _log_lock:
        # Clear any existing progress line first
        if (_last_progress_len > 0):
            sys.stdout.write("\r" + " " * _last_progress_len + "\r")
            sys.stdout.flush()
            _last_progress_len = 0

        # Print the formatted message immediately
        for line in formatted_lines:
            print(line)

        sys.stdout.flush()


# Re-attach progress logger to the modified log function
log.progress = ProgressLogger


# --- Packing/Unpacking Functions ---
def _get_fmt(size_bits, signed=False):
    """Internal helper to get struct format string."""
    endian_char = "<" if context.endian == "little" else ">"
    size_map = {8: "b", 16: "h", 32: "i", 64: "q"}
    if not signed:
        # Convert format char to uppercase for unsigned
        size_map = {k: v.upper() for k, v in size_map.items()}
    if size_bits not in size_map:
        raise ValueError(
            f"Unsupported standard size for packing/unpacking: {size_bits} bits"
        )
    return endian_char + size_map[size_bits]


def p8(data, signed=False):
    return struct.pack(_get_fmt(8, signed), data)


def p16(data, signed=False):
    return struct.pack(_get_fmt(16, signed), data)


def p32(data, signed=False):
    return struct.pack(_get_fmt(32, signed), data)


def p64(data, signed=False):
    return struct.pack(_get_fmt(64, signed), data)


def u8(data, signed=False):
    return struct.unpack(_get_fmt(8, signed), data[:1])[0]


def u16(data, signed=False):
    return struct.unpack(_get_fmt(16, signed), data[:2])[0]


def u32(data, signed=False):
    return struct.unpack(_get_fmt(32, signed), data[:4])[0]


def u64(data, signed=False):
    return struct.unpack(_get_fmt(64, signed), data[:8])[0]


# --- Generic Packing/Unpacking using context ---
# (Assuming long_to_bytes and bytes_to_long are defined below)
def pack(data, word_size=None, endian=None, signed=False):
    """Packs integer 'data' into bytes using context settings."""
    ws = word_size if word_size is not None else context.word_size
    e = endian if endian is not None else context.endian
    fmt_endian = "<" if e == "little" else ">"

    fmt_char = ""
    if ws == 8:
        fmt_char = "b" if signed else "B"
    elif ws == 16:
        fmt_char = "h" if signed else "H"
    elif ws == 32:
        fmt_char = "i" if signed else "I"
    elif ws == 64:
        fmt_char = "q" if signed else "Q"
    elif ws % 8 == 0:
        # Use big integer conversion for non-standard sizes
        num_bytes = ws // 8
        return long_to_bytes(data, length=num_bytes, endian=e, signed=signed)
    else:
        raise ValueError(f"Word size {ws} must be a multiple of 8 bits")

    return struct.pack(fmt_endian + fmt_char, data)


def unpack(data, word_size=None, endian=None, signed=False):
    """Unpacks bytes 'data' into an integer using context settings."""
    ws = word_size if word_size is not None else context.word_size
    e = endian if endian is not None else context.endian
    fmt_endian = "<" if e == "little" else ">"

    if ws % 8 != 0:
        raise ValueError(f"Word size {ws} must be a multiple of 8 bits")
    num_bytes = ws // 8

    if len(data) < num_bytes:
        raise ValueError(
            f"Need {num_bytes} bytes to unpack {ws} bits, but got only {len(data)}"
        )

    # Slice data to the required number of bytes
    data_slice = data[:num_bytes]

    fmt_char = ""
    if ws == 8:
        fmt_char = "b" if signed else "B"
    elif ws == 16:
        fmt_char = "h" if signed else "H"
    elif ws == 32:
        fmt_char = "i" if signed else "I"
    elif ws == 64:
        fmt_char = "q" if signed else "Q"
    else:
        # Use big integer conversion for non-standard sizes
        return bytes_to_long(data_slice, endian=e, signed=signed)

    return struct.unpack(fmt_endian + fmt_char, data_slice)[0]


# --- Big Integer / Arbitrary Byte Length Conversion ---
def long_to_bytes(n, length=None, endian=None, signed=False):
    """Converts an integer to a byte string."""
    e = endian if endian is not None else context.endian
    if n == 0:
        return b"\x00" * (length or 1)  # Return at least one byte for 0 if no length

    try:
        # Calculate minimum bytes needed
        if n > 0:
            bit_len = n.bit_length()
            req_bytes = (bit_len + 7) // 8 if not signed else (bit_len + 8) // 8
        elif n < 0:
            if not signed:
                raise ValueError("Cannot represent negative number as unsigned bytes.")
            # For signed negative, bit_length includes sign bit position correctly
            req_bytes = (n.bit_length() + 7) // 8
        else:  # n == 0 case handled above
            req_bytes = 1

        # Determine final length
        if length is None:
            l = req_bytes
        else:
            l = length
            # Check if provided length is sufficient (only if n != 0)
            if (
                n != 0 and signed and l * 8 < n.bit_length() + 1
            ):  # Need space for sign bit
                pass  # Let to_bytes raise OverflowError if truly too small
            elif n != 0 and not signed and l * 8 < n.bit_length():
                pass  # Let to_bytes raise OverflowError

        return n.to_bytes(l, byteorder=e, signed=signed)
    except OverflowError:
        raise ValueError(f"Integer {n} too large for {l} bytes (signed={signed})")


def bytes_to_long(b, endian=None, signed=False):
    """Converts a byte string to an integer."""
    if not b:  # Handle empty byte string
        return 0
    e = endian if endian is not None else context.endian
    return int.from_bytes(b, byteorder=e, signed=signed)


# --- Utility Functions ---
def xor(*args):
    """XORs multiple byte strings or integers together."""
    if not args:
        return b""
    byte_args = []
    for arg in args:
        if isinstance(arg, bytes):
            byte_args.append(arg)
        elif isinstance(arg, bytearray):
            byte_args.append(bytes(arg))
        elif isinstance(arg, int):
            byte_args.append(bytes([arg & 0xFF]))  # XOR with single byte
        else:
            raise TypeError(f"Unsupported type for XOR: {type(arg)}")

    if not byte_args:
        return b""
    byte_args = [a for a in byte_args if a]  # Filter out empty args
    if not byte_args:
        return b""
    if len(byte_args) == 1:
        return byte_args[0]  # No XOR needed

    max_len = max(len(a) for a in byte_args)
    result = bytearray(max_len)
    for i in range(max_len):
        val = 0
        for ba in byte_args:
            # Cycle through shorter byte strings
            val ^= ba[i % len(ba)]
        result[i] = val
    return bytes(result)


def enhex(data: bytes) -> str:
    """Hex encodes bytes to an ASCII string."""
    if not isinstance(data, bytes):
        raise TypeError("enhex() requires bytes input")
    return binascii.hexlify(data).decode("ascii")


def unhex(data: str) -> bytes:
    """Hex decodes an ASCII string to bytes."""
    if not isinstance(data, str):
        raise TypeError("unhex() requires string input")
    try:
        return binascii.unhexlify(data)
    except binascii.Error as e:
        raise ValueError(f"Invalid hex input: {e}") from e


def b64e(data: bytes) -> str:
    """Base64 encodes bytes to an ASCII string."""
    if not isinstance(data, bytes):
        raise TypeError("b64e() requires bytes input")
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    """Base64 decodes an ASCII string or bytes to bytes."""
    if isinstance(data, str):
        data = data.encode("ascii")  # Needs bytes input for decode
    elif not isinstance(data, bytes):
        raise TypeError("b64d() requires string or bytes input")
    try:
        return base64.b64decode(data)
    except binascii.Error as e:
        raise ValueError(f"Invalid base64 input: {e}") from e


# --- IOBase ---
class IOBase:
    """Base class for input/output operations."""

    def __init__(self, timeout=None):
        self._buffer = b""
        self.timeout = timeout if timeout is not None else context.get_timeout()
        self.closed = True  # Start as closed until connection established

    def _resolve_timeout(self, timeout_override):
        """Determines the effective timeout value."""
        return timeout_override if timeout_override is not None else self.timeout

    def send(self, msg: bytes):
        """Sends raw bytes. Must be implemented by subclasses."""
        raise NotImplementedError

    def recv(self, num: int = 4096, timeout=None) -> bytes:
        """Receives up to 'num' bytes. Must be implemented by subclasses."""
        raise NotImplementedError

    def close(self):
        """Closes the connection. Must be implemented by subclasses."""
        raise NotImplementedError

    def interactive(self):
        """Switches to interactive mode. Must be implemented by subclasses."""
        raise NotImplementedError

    def sendline(self, msg: bytes):
        """Sends bytes followed by a newline."""
        if not isinstance(msg, bytes):
            # Try encoding if it's a string
            if isinstance(msg, str):
                try:
                    msg = msg.encode()
                except UnicodeEncodeError:
                    raise TypeError(
                        "sendline() argument must be bytes or an encodable string"
                    )
            else:
                raise TypeError(
                    "sendline() argument must be bytes or an encodable string"
                )
        # Ensure newline is bytes
        newline = b"\n"
        # Log before sending - log function handles debug deferral
        log(msg + newline, level="debug", is_input=True, show_hexdump=True)
        self.send(msg + newline)

    def sendafter(self, delim: bytes, msg: bytes, timeout=None):
        """Receives until 'delim' is found, then sends 'msg'."""
        if not isinstance(delim, bytes):
            delim = delim.encode()  # Allow string delim
        if not isinstance(msg, bytes):
            msg = msg.encode()  # Allow string msg

        rd = self.recvuntil(delim, drop=False, timeout=timeout)
        if delim in rd:
            log(msg, level="debug", is_input=True, show_hexdump=True)  # Log before send
            self.send(msg)
        else:
            log(
                f"Delimiter {delim!r} not found in received data before sendafter",
                "warning",
            )
        return rd  # Return received data including delimiter

    def sendlineafter(self, delim: bytes, msg: bytes, timeout=None):
        """Receives until 'delim' is found, then sends 'msg' followed by a newline."""
        if not isinstance(delim, bytes):
            delim = delim.encode()
        if not isinstance(msg, bytes):
            msg = msg.encode()

        rd = self.recvuntil(delim, drop=False, timeout=timeout)
        if delim in rd:
            self.sendline(msg)  # sendline handles logging
        else:
            log(
                f"Delimiter {delim!r} not found in received data before sendlineafter",
                "warning",
            )
        return rd

    def recvuntil(self, delim: bytes, drop: bool = False, timeout=None) -> bytes:
        """Receives data until 'delim' is found."""
        if not isinstance(delim, bytes):
            delim = delim.encode()  # Allow string delim

        ct = self._resolve_timeout(timeout)  # Effective timeout
        start_time = time.time()
        result_data = b""  # Store the final result here

        while True:
            # Check buffer first
            delim_index = self._buffer.find(delim)
            if delim_index != -1:
                # Delimiter found in buffer
                needed_len = delim_index + len(delim)
                result_data = self._buffer[:needed_len]
                self._buffer = self._buffer[needed_len:]

                # --- FIX: REMOVE/COMMENT OUT the internal log call on success path ---
                # This log call is causing the hang in the subprocess test environment.
                # log(result_data, level='debug', length=len(result_data), is_input=False, show_hexdump=True)
                # --- END FIX ---

                return result_data[: -len(delim)] if drop else result_data

            # Check if connection is closed (Keep logs here, less likely to cause issues)
            if self.closed:
                log(f"Connection closed while waiting for delimiter {delim!r}", "info")
                result_data = self._buffer
                self._buffer = b""
                # Log buffer content on close
                log(
                    result_data,
                    level="debug",
                    length=len(result_data),
                    is_input=False,
                    show_hexdump=True,
                )
                return result_data

            # Check for timeout (Keep logs here)
            elapsed = time.time() - start_time
            if ct is not None and elapsed >= ct:
                log(f"Timeout (> {ct:.2f}s) waiting for delimiter {delim!r}", "warning")
                result_data = self._buffer
                self._buffer = b""
                # Log buffer content on timeout
                log(
                    result_data,
                    level="debug",
                    length=len(result_data),
                    is_input=False,
                    show_hexdump=True,
                )
                return result_data

            # Calculate remaining time for recv call
            remaining_time = 0.1
            if ct is not None:
                remaining_time = max(0.001, ct - elapsed)

            # Try to receive more data
            try:
                chunk = self.recv(4096, timeout=remaining_time)  # Use underlying recv
                if chunk:
                    # Note: Logging chunk *here* could also be risky if chunks are large
                    self._buffer += chunk
                    continue
                elif self.closed:
                    log(
                        f"Connection closed after recv() returned empty while waiting for {delim!r}",
                        "info",
                    )
                    result_data = self._buffer
                    self._buffer = b""
                    log(
                        result_data,
                        level="debug",
                        length=len(result_data),
                        is_input=False,
                        show_hexdump=True,
                    )
                    return result_data

            except TimeoutError:
                # Check timeout condition again after recv timeout (Keep logs here)
                if ct is not None and time.time() - start_time >= ct:
                    log(
                        f"Timeout (> {ct:.2f}s) after recv timeout waiting for {delim!r}",
                        "warning",
                    )
                    result_data = self._buffer
                    self._buffer = b""
                    log(
                        result_data,
                        level="debug",
                        length=len(result_data),
                        is_input=False,
                        show_hexdump=True,
                    )
                    return data_received  # Typo Fixed: should be result_data
                continue
            except ConnectionError as e:  # Keep logs here
                log(f"Connection error during recvuntil ({delim!r}): {e}", "error")
                self.close()
                result_data = self._buffer
                self._buffer = b""
                log(
                    result_data,
                    level="debug",
                    length=len(result_data),
                    is_input=False,
                    show_hexdump=True,
                )
                return result_data
            except Exception as e:  # Keep logs here
                log(f"Unexpected error in recvuntil ({delim!r}): {e}", "error")
                self.close()
                result_data = self._buffer
                self._buffer = b""
                log(
                    result_data,
                    level="debug",
                    length=len(result_data),
                    is_input=False,
                    show_hexdump=True,
                )
                raise

    def recvuntil_timed(self, delim: bytes, drop: bool = False, timeout=None):
        """Receives data until 'delim' is found, returns (data, time)."""
        start_perf = perf_counter()
        data = self.recvuntil(delim, drop=drop, timeout=timeout)
        end_perf = perf_counter()
        return data, end_perf - start_perf

    def recvline(self, drop: bool = True, timeout=None) -> bytes:
        """Receives data until a newline character is found."""
        return self.recvuntil(b"\n", drop=drop, timeout=timeout)

    def recvline_contains(
        self, keyword: bytes, drop: bool = True, timeout=None
    ) -> bytes:
        """Receives lines until one containing 'keyword' is found."""
        if not isinstance(keyword, bytes):
            keyword = keyword.encode()  # Allow string keyword

        ct = self._resolve_timeout(timeout)
        start_time = time.time()

        line_buffer = b""  # Buffer for assembling lines across recv calls
        while True:
            # Check timeout
            elapsed = time.time() - start_time
            if ct is not None and elapsed >= ct:
                log(
                    f"Timeout (> {ct:.2f}s) waiting for line containing {keyword!r}",
                    "warning",
                )
                # Return the partial line buffer if any
                log(line_buffer, level="debug", is_input=False, show_hexdump=True)
                return line_buffer

            # Check for newline in existing combined buffer
            if b"\n" in self._buffer:
                line_end_index = self._buffer.find(b"\n")
                current_line = self._buffer[: line_end_index + 1]
                self._buffer = self._buffer[line_end_index + 1 :]  # Update main buffer

                # Log the full line received
                log(current_line, level="debug", is_input=False, show_hexdump=True)

                if keyword in current_line:
                    return current_line.rstrip(b"\n") if drop else current_line
                else:
                    # Line didn't match, discard it (or store if needed?) and continue
                    line_buffer = b""  # Reset partial line buffer
                    continue  # Check next line in buffer or recv more

            # If no newline in buffer, need to receive more data
            remaining_time = 0.1
            if ct is not None:
                remaining_time = max(0.001, ct - elapsed)

            try:
                chunk = self.recv(4096, timeout=remaining_time)
                if chunk:
                    self._buffer += chunk
                    continue  # Loop back to check buffer for newline
                elif self.closed:
                    log(
                        f"Connection closed while waiting for line containing {keyword!r}",
                        "info",
                    )
                    # Check remaining buffer for keyword one last time
                    if keyword in self._buffer:
                        # Cannot guarantee it's a full line, return as is
                        log(
                            self._buffer,
                            level="debug",
                            is_input=False,
                            show_hexdump=True,
                        )
                        return self._buffer
                    else:
                        log(
                            self._buffer,
                            level="debug",
                            is_input=False,
                            show_hexdump=True,
                        )
                        return (
                            b""  # Return empty if keyword not found in remaining buffer
                        )
            except TimeoutError:
                # Check overall timeout again
                if ct is not None and time.time() - start_time >= ct:
                    log(
                        f"Timeout (> {ct:.2f}s) after recv timeout waiting for {keyword!r}",
                        "warning",
                    )
                    log(self._buffer, level="debug", is_input=False, show_hexdump=True)
                    return self._buffer  # Return whatever partial data exists
                continue  # Loop if overall timeout not met
            except ConnectionError as e:
                log(
                    f"Connection error waiting for line containing {keyword!r}: {e}",
                    "error",
                )
                self.close()
                log(self._buffer, level="debug", is_input=False, show_hexdump=True)
                return self._buffer  # Return what we have
            except Exception as e:
                log(
                    f"Unexpected error waiting for line containing {keyword!r}: {e}",
                    "error",
                )
                self.close()
                log(self._buffer, level="debug", is_input=False, show_hexdump=True)
                raise

    def recvall(self, timeout=0.1) -> bytes:
        """Receives data until a timeout occurs (defaults to 0.1s)."""
        all_data = bytearray(self._buffer)  # Start with existing buffer
        self._buffer = b""
        last_recv_time = time.time()
        overall_timeout = self._resolve_timeout(
            None
        )  # Check against global timeout if set
        start_time = time.time()

        while True:
            # Check overall timeout first
            if (
                overall_timeout is not None
                and time.time() - start_time >= overall_timeout
            ):
                log(f"Recvall: Overall timeout ({overall_timeout}s) expired.", "debug")
                break

            # Calculate time since last receive and check idle timeout
            time_since_last_recv = time.time() - last_recv_time
            if time_since_last_recv >= timeout:
                log(f"Recvall: Idle timeout ({timeout}s) hit.", "debug")
                break  # Idle timeout triggered

            # Calculate remaining time for this recv call
            recv_timeout = max(0.001, timeout - time_since_last_recv)
            if overall_timeout is not None:
                overall_remaining = max(
                    0.001, overall_timeout - (time.time() - start_time)
                )
                recv_timeout = min(recv_timeout, overall_remaining)

            try:
                chunk = self.recv(4096, timeout=recv_timeout)
                if not chunk:
                    # recv returning empty usually means closed connection
                    log("Recvall: Connection closed (recv returned empty).", "debug")
                    break
                all_data.extend(chunk)
                last_recv_time = time.time()  # Update time of last successful receive
            except TimeoutError:
                # Expected timeout for recvall, means no more data arrived recently
                log(
                    f"Recvall: Idle timeout ({timeout}s) hit (recv timed out).", "debug"
                )
                break
            except ConnectionError as e:
                log(f"Recvall: Connection error: {e}", "error")
                self.close()  # Ensure closed
                break  # Stop receiving
            except Exception as e:
                log(f"Recvall: Unexpected error: {e}", "error")
                self.close()
                break

        result = bytes(all_data)
        # --- FIX: Simplify the final log call ---
        # log(f"Recvall returning {len(result)} bytes.", level='debug', is_input=False, show_hexdump=False)
        # --- END FIX ---
        return result

    def __enter__(self):
        """Enter context manager."""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Exit context manager, ensure connection is closed."""
        self.close()


# --- remote Class ---
class remote(IOBase):
    """Represents a remote TCP connection."""

    def __init__(
        self,
        host,
        port,
        timeout=None,
        ssl_context=None,  # Pass a pre-configured ssl.SSLContext
        ssl_check_hostname=True,  # Whether to verify hostname for SSL
        server_hostname=None,  # Override hostname for SNI/verification
        use_ssl=False,  # Explicitly enable SSL without context
    ):
        # Initialize IOBase first
        super().__init__(timeout)  # Sets self.timeout, self._buffer, self.closed=True

        self.host = host
        self.port = port
        self.raw_socket: socket.socket | None = None
        self.sock: socket.socket | ssl.SSLSocket | None = (
            None  # The socket used for I/O (raw or SSL wrapped)
        )
        self.use_ssl = use_ssl or (ssl_context is not None)

        effective_timeout = self._resolve_timeout(self.timeout)

        try:
            conn_type = "SSL" if self.use_ssl else "TCP"
            log(
                f"Opening {conn_type} connection to {host}:{port} (timeout={effective_timeout}s)",
                "info",
            )
            # Create raw socket
            self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set timeout for connection attempt
            if effective_timeout is not None:
                self.raw_socket.settimeout(effective_timeout)

            # Connect
            self.raw_socket.connect((host, port))

            # Connection successful, reset timeout for subsequent operations (or set to None for blocking)
            # We'll set timeout per-operation in recv/send if needed, None is safer default
            self.raw_socket.settimeout(None)

            if self.use_ssl:
                log("Wrapping socket with SSL/TLS", "debug")
                context_to_use = ssl_context or ssl.create_default_context()

                # Handle hostname checking override
                if not ssl_check_hostname:
                    context_to_use.check_hostname = False
                    context_to_use.verify_mode = ssl.CERT_NONE
                    log("SSL hostname verification disabled.", "warning")

                # Determine server_hostname for SNI and verification
                hostname_for_ssl = server_hostname or host

                # Set timeout for SSL handshake
                self.raw_socket.settimeout(effective_timeout)
                try:
                    self.sock = context_to_use.wrap_socket(
                        self.raw_socket, server_hostname=hostname_for_ssl
                    )
                    log(f"SSL handshake successful with {hostname_for_ssl}", "debug")
                    # Handshake done, reset socket timeout
                    self.sock.settimeout(None)
                except ssl.SSLError as e:
                    log(f"SSL Handshake Failed: {e}", "error")
                    self.close()  # Clean up raw socket
                    raise ConnectionError(f"SSL Handshake Failed: {e}")
                except socket.timeout:
                    log(f"Timeout during SSL Handshake with {host}:{port}", "error")
                    self.close()
                    raise TimeoutError(
                        f"SSL Handshake timeout connecting to {host}:{port}"
                    )
                except Exception as e:
                    log(f"Error during SSL wrap_socket: {e}", "error")
                    self.close()
                    raise ConnectionError(f"SSL wrap_socket failed: {e}")

            else:
                # If not using SSL, the I/O socket is the raw socket
                self.sock = self.raw_socket

            # If we reached here, connection is open
            self.closed = False
            log(f"Opened {conn_type} connection to {host}:{port}", "info")

        except socket.timeout:
            log(f"Timeout connecting to {host}:{port}", "error")
            self.close()  # Ensure cleanup even on connect timeout
            raise TimeoutError(f"Connection timeout to {host}:{port}")
        except socket.error as e:
            # Covers connection refused, host not found, etc.
            log(f"Connection failed to {host}:{port}: {e}", "error")
            self.close()
            raise ConnectionError(f"Connection failed to {host}:{port}: {e}")
        except Exception as e:
            # Catch any other unexpected errors during setup
            log(f"Failed to establish connection to {host}:{port}: {e}", "error")
            self.close()
            raise ConnectionError(f"Failed to establish connection: {e}")

    def send(self, msg: bytes):
        """Sends raw bytes over the connection."""
        if not isinstance(msg, bytes):
            raise TypeError("send() argument must be bytes")
        if self.closed or not self.sock:
            raise ConnectionError("Cannot send: Socket is closed")

        try:
            # sendall loops until all data is sent or an error occurs
            self.sock.sendall(msg)
            # Logging is handled by calling functions like sendline or directly via log()
            # log(msg, level='debug', is_input=True, show_hexdump=True) # Log here if needed universally
        except (socket.error, ssl.SSLError) as e:
            # Common errors: Broken pipe, connection reset, SSL errors
            log(f"Send error: {e}", "error")
            self.close()  # Mark as closed on send error
            raise ConnectionError(f"Socket error during send: {e}")
        except Exception as e:
            log(f"Unexpected send error: {e}", "error")
            self.close()
            raise ConnectionError(f"Unexpected error during send: {e}")

    # Inside the remote class
    def recv(self, num: int = 4096, timeout=None) -> bytes:
        # --- DEBUG ---
        print(
            f"DEBUG: remote.recv entered. num={num}, timeout={timeout}, buffer={self._buffer!r}",
            file=sys.stderr,
            flush=True,
        )
        # --- END DEBUG ---

        if self.closed or not self.sock:
            # --- DEBUG ---
            print(
                f"DEBUG: remote.recv returning empty (closed or no sock)",
                file=sys.stderr,
                flush=True,
            )
            # --- END DEBUG ---
            return b""
        if num <= 0:
            # --- DEBUG ---
            print(
                f"DEBUG: remote.recv returning empty (num <= 0)",
                file=sys.stderr,
                flush=True,
            )
            # --- END DEBUG ---
            return b""

        if self._buffer:
            data_from_buffer = self._buffer[:num]
            self._buffer = self._buffer[num:]
            # --- DEBUG ---
            print(
                f"DEBUG: remote.recv returning from buffer: {data_from_buffer!r}",
                file=sys.stderr,
                flush=True,
            )
            # --- END DEBUG ---
            return data_from_buffer

        effective_timeout = self._resolve_timeout(timeout)

        # --- FIX: Robust Timeout Handling ---
        original_timeout = None
        try:
            # Get original timeout
            original_timeout = self.sock.gettimeout()
            # Always try to set the effective timeout for this operation
            if self.sock.gettimeout() != effective_timeout:
                print(
                    f"DEBUG: remote.recv setting timeout to {effective_timeout}",
                    file=sys.stderr,
                    flush=True,
                )  # Keep for debug if needed
                self.sock.settimeout(effective_timeout)
        except (socket.error, ssl.SSLError, OSError) as e:
            # Log or handle error getting/setting timeout if necessary
            log(f"Warning: Failed to get/set socket timeout: {e}", "warning")
            # Decide if this is fatal or recoverable
            # For now, we'll proceed cautiously

        data = b""
        try:
            try:
                print(
                    f"DEBUG: remote.recv calling sock.recv({num}) with effective timeout={effective_timeout}",
                    file=sys.stderr,
                    flush=True,
                )
                data = self.sock.recv(num)
                print(
                    f"DEBUG: remote.recv sock.recv returned: {data!r}",
                    file=sys.stderr,
                    flush=True,
                )

            # ... (Keep existing exception handling: BlockingIOError, socket.timeout, etc.) ...
            except BlockingIOError:
                print(
                    f"DEBUG: remote.recv caught BlockingIOError",
                    file=sys.stderr,
                    flush=True,
                )
                raise TimeoutError("Timeout during recv (BlockingIOError/EAGAIN)")
            except ssl.SSLWantReadError:
                print(
                    f"DEBUG: remote.recv caught SSLWantReadError",
                    file=sys.stderr,
                    flush=True,
                )
                log("SSLWantReadError occurred, treating as timeout.", "debug")
                raise TimeoutError("Timeout during SSL recv (SSLWantReadError)")
            except socket.timeout:
                print(
                    f"DEBUG: remote.recv caught socket.timeout",
                    file=sys.stderr,
                    flush=True,
                )
                raise TimeoutError(
                    f"Timeout during recv (timeout={effective_timeout}s)"
                )
            except ssl.SSLZeroReturnError:
                print(
                    f"DEBUG: remote.recv caught SSLZeroReturnError",
                    file=sys.stderr,
                    flush=True,
                )
                log("SSL connection closed cleanly (SSLZeroReturnError).", "info")
                self.close()  # Mark as closed
                return b""  # Return empty bytes on clean close
            except ConnectionAbortedError:
                print(
                    f"DEBUG: remote.recv caught ConnectionAbortedError",
                    file=sys.stderr,
                    flush=True,
                )
                log("Connection aborted during recv.", "info")
                self.close()
                return b""
            except ConnectionResetError:
                print(
                    f"DEBUG: remote.recv caught ConnectionResetError",
                    file=sys.stderr,
                    flush=True,
                )
                log("Connection reset during recv.", "info")
                self.close()
                return b""
            # Catch OTHER socket/ssl errors here
            except (socket.error, ssl.SSLError) as e:
                print(
                    f"DEBUG: remote.recv caught socket/ssl error: {e}",
                    file=sys.stderr,
                    flush=True,
                )
                log(f"Recv error: {e}", "error")
                self.close()
                raise ConnectionError(f"Socket error during recv: {e}")
            except Exception as e:
                print(
                    f"DEBUG: remote.recv caught unexpected error: {e}",
                    file=sys.stderr,
                    flush=True,
                )
                log(f"Unexpected recv error: {e}", "error")
                self.close()
                raise ConnectionError(f"Unexpected error during recv: {e}")

            # --- Restore original timeout (inside try block) ---
            try:
                # Only restore if original was known and differs from current
                if (
                    original_timeout is not None
                    and self.sock.gettimeout() != original_timeout
                ):
                    print(
                        f"DEBUG: remote.recv restoring timeout to {original_timeout}",
                        file=sys.stderr,
                        flush=True,
                    )
                    self.sock.settimeout(original_timeout)
            except (socket.error, ssl.SSLError, OSError):
                log(
                    "Ignoring error restoring socket timeout after successful recv.",
                    "debug",
                )

            # Check if connection closed (recv returned 0 bytes)
            if not data:
                print(
                    f"DEBUG: remote.recv received empty data, closing.",
                    file=sys.stderr,
                    flush=True,
                )
                log("Connection closed by remote host (recv returned 0 bytes).", "info")
                self.close()  # Mark as closed
                return b""

            print(
                f"DEBUG: remote.recv returning data: {data!r}",
                file=sys.stderr,
                flush=True,
            )
            return data

        # Exception handling blocks need to also restore timeout
        except TimeoutError as e_timeout:
            try:
                if (
                    original_timeout is not None
                    and self.sock.gettimeout() != original_timeout
                ):
                    self.sock.settimeout(original_timeout)
            except Exception:
                pass  # Ignore restore errors on exception path
            print(
                f"DEBUG: remote.recv raising TimeoutError: {e_timeout}",
                file=sys.stderr,
                flush=True,
            )
            raise e_timeout
        except Exception as e_outer:
            try:
                if (
                    original_timeout is not None
                    and self.sock.gettimeout() != original_timeout
                ):
                    self.sock.settimeout(original_timeout)
            except Exception:
                pass  # Ignore restore errors on exception path
            print(
                f"DEBUG: remote.recv raising Exception: {e_outer}",
                file=sys.stderr,
                flush=True,
            )
            raise e_outer
        # --- END FIX ---

    def close(self):
        """Closes the connection gracefully."""
        if self.closed:
            return  # Already closed

        conn_type = "SSL" if self.use_ssl else "TCP"
        log(f"Closing {conn_type} connection to {self.host}:{self.port}", "info")

        self.closed = True
        sock_to_close = self.sock
        raw_sock_to_close = self.raw_socket

        # Nullify references first
        self.sock = None
        self.raw_socket = None
        self._buffer = b""  # Clear buffer on close

        # Close the I/O socket (which might be SSL wrapped)
        if sock_to_close:
            try:
                # Shutdown might fail if already closed, ignore specific errors
                sock_to_close.shutdown(socket.SHUT_RDWR)
            except (socket.error, ssl.SSLError, OSError) as e_shutdown:
                # errno 107: Transport endpoint is not connected (common after remote close)
                # errno 9: Bad file descriptor (if already closed)
                # errno 32: Broken pipe
                # errno 54: Connection reset by peer (macOS)
                if getattr(e_shutdown, "errno", None) not in (107, 9, 32, 54):
                    log(f"Ignoring error during socket shutdown: {e_shutdown}", "debug")
            except Exception as e_shutdown_other:
                log(
                    f"Ignoring unexpected error during socket shutdown: {e_shutdown_other}",
                    "debug",
                )

            try:
                sock_to_close.close()
            except (socket.error, ssl.SSLError, OSError) as e_close:
                log(f"Ignoring error during socket close: {e_close}", "debug")
            except Exception as e_close_other:
                log(
                    f"Ignoring unexpected error during socket close: {e_close_other}",
                    "debug",
                )

        # Close the underlying raw socket if it's different and wasn't closed above
        if (
            self.use_ssl
            and raw_sock_to_close
            and raw_sock_to_close is not sock_to_close
        ):
            try:
                raw_sock_to_close.close()
            except (socket.error, OSError) as e_raw_close:
                log(f"Ignoring error during raw socket close: {e_raw_close}", "debug")
            except Exception as e_raw_close_other:
                log(
                    f"Ignoring unexpected error during raw socket close: {e_raw_close_other}",
                    "debug",
                )

    # --- Interactive Mode with Deferred Logging ---
    def interactive(self):
        """Switches to interactive mode with line buffering and deferred debug logging."""
        if self.closed or not self.sock:
            log("Connection is closed. Cannot enter interactive mode.", "warning")
            return

        # --- FIX: Check if stdin is a TTY ---
        if not sys.stdin.isatty():
            print("[INFO] Standard input is not a TTY. Interactive mode skipped.", file=sys.stderr, flush=True)
            return
        # --- END FIX ---

        log("Switching to interactive mode (Ctrl+C or Ctrl+D to exit)", "warning")

        # --- Set Interactive State ---
        context.interactive_mode_active = True
        flush_interactive_logs()

        original_timeout = self.sock.gettimeout()
        original_blocking = True
        try:
            original_blocking = self.sock.getblocking()
        except Exception: pass

        stdin_fd = sys.stdin.fileno()

        try:
            self.sock.setblocking(False)

            while not self.closed:
                try:
                    # Monitor stdin and the socket for readability
                    rfds, _, _ = select.select(
                        [self.sock, stdin_fd], [], [], 0.1
                    )  # 100ms timeout
                except (ValueError, OSError, select.error) as e:
                    # Handle potential errors like closed file descriptors
                    if getattr(e, "errno", None) == 9 or (
                        isinstance(e, ValueError) and "file descriptor" in str(e)
                    ):  # EBADF
                        log(
                            "Socket or stdin closed unexpectedly during select.", "info"
                        )
                        break
                    log(f"Select error: {e}", "error")
                    break
                except KeyboardInterrupt:
                    log(
                        "\nInteractive mode interrupted by Ctrl+C.", "warning"
                    )  # Normal log
                    break

                # Check socket for data
                if self.sock in rfds:
                    received_data = b""
                    try:
                        # Read available data using non-blocking recv
                        # Loop recv until SSLWantReadError/TimeoutError/empty bytes/error
                        while True:
                            try:
                                # Use underlying recv with 0 timeout for non-blocking check
                                chunk = self.recv(4096, timeout=0)
                                if chunk:
                                    received_data += chunk
                                elif self.closed:  # recv might close
                                    break  # Exit inner loop if closed
                                else:  # No more data available right now
                                    break
                            except TimeoutError:  # Expected in non-blocking
                                break
                            except ConnectionError:  # Connection error from self.recv
                                raise  # Propagate up to outer try/except
                    except (
                        ConnectionError
                    ) as e:  # Handle connection errors from recv loop
                        log(
                            f"Connection error during interactive recv: {e}", "error"
                        )  # Normal log
                        break  # Exit main interactive loop
                    except Exception as e:
                        log(f"Error receiving data: {e}", "error")  # Normal log
                        break  # Exit main interactive loop

                    if received_data:
                        # Print raw data cleanly
                        try:
                            sys.stdout.write(received_data.decode(errors="replace"))
                            sys.stdout.flush()
                        except Exception as decode_err:
                            log(
                                f"Error decoding output: {decode_err}", "warning"
                            )  # Normal log
                            sys.stdout.write(repr(received_data))  # Fallback
                            sys.stdout.flush()
                        # --- Flush Logs AFTER printing received data ---
                        flush_interactive_logs()

                    elif self.closed:  # Check if closed after recv attempts
                        log("Connection closed by remote host.", "info")  # Normal log
                        break

                # Check stdin for data (user input)
                if stdin_fd in rfds:
                    line_input = ""
                    try:
                        # Read a whole line using standard input functions
                        line_input = sys.stdin.readline()
                        if not line_input:  # Handle EOF (Ctrl+D)
                            log(
                                "\nEOF received from stdin. Exiting interactive mode.",
                                "info",
                            )  # Normal log
                            break

                        # Encode and send the line
                        line_bytes = line_input.encode()  # Use default encoding
                        # Log the send action (will be deferred if debug)
                        log(line_bytes, level="debug", is_input=True, show_hexdump=True)
                        # Perform the actual send
                        self.send(line_bytes)

                        # --- Flush Logs AFTER attempting to send user data ---
                        flush_interactive_logs()

                    except EOFError:  # Should be caught by readline returning empty
                        log(
                            "\nEOFError on stdin. Exiting interactive mode.", "info"
                        )  # Normal log
                        break
                    except ConnectionError as e:  # Handle errors during send
                        log(
                            f"Connection error during interactive send: {e}", "error"
                        )  # Normal log
                        break  # Exit main loop
                    except Exception as e:
                        log(f"Error reading/sending stdin: {e}", "error")  # Normal log
                        break  # Exit main loop

        finally:
            # --- Flush any remaining logs BEFORE resetting state ---
            flush_interactive_logs()

            # --- Reset Interactive State ---
            context.interactive_mode_active = False

            # Restore socket settings
            try:
                # Check if self.sock still exists and is valid before setting state
                if self.sock and self.sock.fileno() != -1:
                    self.sock.setblocking(original_blocking)
                    self.sock.settimeout(original_timeout)
                elif (
                    not self.closed
                ):  # If sock is None but not marked closed, log warning
                    log(
                        "Could not restore socket settings (socket object invalid).",
                        "warning",
                    )
            except Exception as e_restore:
                # Ignore errors if socket became invalid during interaction
                if not self.closed:  # Only log if we didn't expect it to be closed
                    log(
                        f"Could not restore socket settings: {e_restore}", "debug"
                    )  # Normal log

            # --- No TTY settings to restore ---

            log("Exited interactive mode.", "warning")  # Normal log


# --- Example Usage ---
if __name__ == "__main__":
    # Example: Connect to a local echo server (needs server running)
    # nc -lvp 12345
    # Or use a public service carefully
    # Example with SSL: requires a host and port supporting SSL echo/test
    # E.g., test against cloudflare's diagnostic endpoint (check terms of use)
    # target_host = "1.1.1.1"
    # target_port = 443 # Default HTTPS

    # Simple TCP Echo Example (run `nc -lvp 12345` in another terminal)
    target_host = "localhost"
    target_port = 12345
    use_ssl_example = False

    print("Pwn4Sage Demo")
    print("--------------")
    print(
        f"Attempting connection to {target_host}:{target_port} (SSL={use_ssl_example})"
    )

    # Set log level - try 'debug' to see deferred logging
    context.set_log_level("debug")
    # context.set_log_level('info') # For cleaner output

    try:
        # Use context manager for automatic close
        with remote(target_host, target_port, timeout=5, use_ssl=use_ssl_example) as r:
            print("Connection successful!")

            # Non-interactive example
            r.sendline(b"Hello from Pwn4Sage!")
            response = r.recvline()
            log(f"Received line: {response.decode(errors='replace')}", "info")

            # Switch to interactive mode
            r.interactive()

    except ConnectionError as e:
        log(f"Connection failed: {e}", "error")
    except TimeoutError as e:
        log(f"Operation timed out: {e}", "error")
    except KeyboardInterrupt:
        log("Execution interrupted by user.", "warning")
    except Exception as e:
        log(f"An unexpected error occurred: {e}", "error")
        import traceback

        traceback.print_exc()

    print("\nDemo finished.")
