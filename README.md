# Pwn4Sage's Guide

不支持输出调试级别信息

As we all know, we cannot use **pwntools** directly in **SageMath**.

In order to solve this problem, you can use Linux.

However, I realized that Cryptor does not need all the complex functions in Pwntools.

In fact, we always use some functions in Pwntools, such as `recvline()`, `sendline()` and other functions related to receiving and sending data.

Finally, when I found that **socket** can be used normally in SageMath, I decided to write a **Simplified pwntools**.

Pwn4Sage contains the following functions (if you don't know the specific use and details, you can check in the relevant documents of pwntools):

- `send(msg)`
- `sendline(msg)`
- `recv(num)`
- `recvuntil(msg)`
- `recvline()`
- `recvline_contains(key_words)`
- `sendafter(delim, data, timeout)`
- `interactive()`
- `close()`

## Installation


This simple python script is available on PyPI and can be installed via pip. 

- `pip install Pwn4Sage`

In the notebook of SageMath, you can use `!pip install Pwn4Sage` to install.

## Usage

```python
from Pwn4Sage.pwn import *
s = remote('39.105.144.62', 2022)
# print(s.sendafter(b'[+] Plz tell me XXXX:', b'1234\n'))
# print(s.recvline())

# s.sendafter(b'[+] Plz tell me XXXX:', b'1234\n'))
# print(s.recvline_contains(b'XXXX'))
s.interactive()
```



