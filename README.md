# Pwn4Sage's Guide

<img width="766" alt="截屏2024-03-23 02 26 11" src="https://github.com/n-WN/Pwn4Sage/assets/30841158/a082f0c8-4705-494f-89d3-d8dde9b94c7e">

还有bug, 不建议在比赛中使用

There are also bugs, not recommended for use in matches

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

## Import styles

- `import pwn` then `pwn.process(...)`
- or `from pwn import *` then `process(...)`

Both are supported. `pwn` is also available when importing `*` for convenience.

## Logging and Observability

You can tune logs via `context(...)` or attribute assignment:

- `context.log_level`: `debug|info|warning|error`
- `context.log_timestamps`: add timestamps
- `context.log_preview`: preview length for inline logs
- `context.log_hex`: show hex instead of escaped text
- `context.debug_split_small_sends`: split very small sends and log per byte
- `context.wiretap`: set a global sink (filepath or binary file-like) to mirror raw IO

Per-tube helpers:

- `tube.stats()` returns `bytes_sent/bytes_recv/buffered/created_at/last_*` and `closed`
- `tube.reset_stats()` resets counters
- `tube.peek(n)` inspects buffered data without consuming
- `tube.wiretap(path_or_stream)` mirrors raw IO for this tube (auto-closed when the tube closes if opened by path)

Delimiter behavior for `send*after`:

- By default, Pwn4Sage strictly matches the delimiter (like pwntools).
- If you prefer auto-consuming a single newline after the delimiter (common in prompt-style outputs), enable:

  ```python
  context.consume_delim_newline = True
  ```

## Installation


This simple python script is available on PyPI and can be installed via pip. 

- `pip install Pwn4Sage`

In the notebook of SageMath, you can use `%pip install Pwn4Sage` to install.

## Usage

```python
from Pwn4Sage.pwn import *
context.log_level = "debug"  # optional
s = remote('39.105.144.62', 2022)
# print(s.sendafter(b'[+] Plz tell me XXXX:', b'1234\n'))
# print(s.recvline())

# s.sendafter(b'[+] Plz tell me XXXX:', b'1234\n'))
# print(s.recvline_contains(b'XXXX'))
s.interactive()
```



