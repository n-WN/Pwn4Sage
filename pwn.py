#!/usr/bin/env python3
# _*_ coding: utf-8 _*_
import socket


class remote():
    def __init__(self, HOST, PORT):
        self.sh = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        p = (HOST, PORT)
        self.sh.connect(p)

    def send(self, msg):
        assert type(msg) == type(b'0HB')
        self.sh.send(msg)

    def sendline(self, msg: bytes):
        assert type(msg) == type(b'0HB')
        msg += b'\n'
        self.sh.send(msg)

    def recv(self, num: int):
        return self.sh.recv(num)

    def recvuntil(self, msg):
        assert type(msg) == type(b'0HB')
        tmp = b''
        while msg not in tmp:
            tmp += self.sh.recv(1)
        return tmp

    def recvline(self):
        tmp = self.recvuntil(b'\n')
        return tmp

    def recvline_contains(self, key):
        assert type(key) == type(b'0HB')
        self.sh.settimeout(0.3)
        while True:
            try:
                res = self.recvline()
                if res == b'':
                    raise "Message does not contain!"
                if key in res:
                    return res.strip(b'\n')

            except:
                raise "Message does not contain!"

    def sendafter(self, delim, data, timeout=1):
        assert type(delim) == type(b'0HB')
        assert type(data) == type(b'0HB')
        self.sh.settimeout(timeout)
        res = self.recvuntil(delim)
        self.sh.send(data)
        return res

    def interactive(self):  # 得想办法判断是否已接受完数据 https://blog.csdn.net/qq_37435462/article/details/125796214
        self.sh.settimeout(0.3)
        while True:
            res = b''
            while True:
                try:
                    tmp = self.recv(1024)  # no recvline
                    if tmp == b'':
                        break
                    res += tmp
                except:
                    break
            if res == b'':
                self.sh.close()
                break
            print(res.decode())
            opt = input()
            self.sendline(opt.encode())

    def close(self):
        self.sh.close()
