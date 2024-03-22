#!/usr/bin/env python3
# _*_ coding: utf-8 _*_
import socket
import select
import sys

class context:
    log_level = "info"

    @staticmethod
    def set_log_level(level):
        context.log_level = level

def log(message, level="info", length=None, interactive_mode=False, is_input=False):
    colors = {
        "info": "\033[94m",
        "debug": "\033[92m",
        "warning": "\033[93m",
        "error": "\033[91m",
        "input": "\033[95m",
        "output": "\033[96m"
    }
    reset = "\033[0m"
    action = "Received" if not is_input else "Sent"
    colored_action = f"{colors.get('input' if is_input else 'output', '')}{action}{reset}"
    prefix = ""
    if interactive_mode:
        prefix = "[IN]" if is_input else "[OUT]"
        colored_prefix = f"{colors.get('input' if is_input else 'output', '')}{prefix}{reset}"
        colored_level_tag = f"{colors.get(level, '')}[{level.upper()}]{reset}"
        message_format = f"{colored_level_tag} {colored_prefix} {colored_action} {length} bytes:"
    else:
        colored_level_tag = f"{colors.get(level, '')}[{level.upper()}]{reset}"
        message_format = f"{colored_level_tag} {colored_action} {length} bytes:" if length is not None else f"{colored_level_tag}"
    if length is not None:
        print(message_format)
        for line in message.splitlines():
            print(f"    {line}")
    else:
        for line in message.splitlines():
            print(f"{message_format} {line}")

class remote:
    def __init__(self, HOST, PORT):
        self.sh = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sh.connect((HOST, PORT))
        log(f"Connected to {HOST}:{PORT}", "info")

    def send(self, msg):
        assert isinstance(msg, bytes)
        self.sh.send(msg)
        log(msg, "debug", len(msg), interactive_mode=True, is_input=True)

    def sendline(self, msg: bytes):
        self.send(msg + b'\n')

    def recv(self, num: int):
        data = self.sh.recv(num)
        if context.log_level == "debug":
            log(data, "debug", len(data), interactive_mode=True)
        return data

    def recvuntil(self, msg):
        assert isinstance(msg, bytes)
        tmp = b''
        while msg not in tmp:
            tmp += self.sh.recv(1)
        if context.log_level == "debug":
            log(tmp, "debug", len(tmp), interactive_mode=True)
        return tmp

    def recvline(self):
        return self.recvuntil(b'\n')

    def recvline_contains(self, keyword):
        assert isinstance(keyword, bytes)
        line = b''
        while True:
            line = self.recvline()
            if keyword in line:
                return line

    def sendafter(self, delim, msg):
        assert isinstance(delim, bytes) and isinstance(msg, bytes)
        self.recvuntil(delim)
        self.send(msg)

    def close(self):
        self.sh.close()
        log("Connection closed", "info")

    def interactive(self):
        # 特殊染色
        print("\033[93m[Switched]\033[0m to interactive mode")
        try:
            while True:
                # 使用float()确保timeout参数是浮点数类型
                ready = select.select([self.sh, sys.stdin], [], [], float(0.1))
                if self.sh in ready[0]:
                    data = self.sh.recv(4096)
                    if not data:
                        log("Connection closed by remote host", "info")
                        break
                    log(data, "info", len(data), interactive_mode=True)
                if sys.stdin in ready[0]:
                    input_data = input().encode() + b'\n'
                    self.send(input_data)
        except KeyboardInterrupt:
            log("Interactive session ended by user", "info")
        finally:
            self.close()

# tesk
"""
if __name__ == "__main__":
    context.set_log_level("debug")
    r = remote("titan.picoctf.net", 52525)
    r.interactive()
    # r.sendline(b"hello")
    # r.close()
"""
