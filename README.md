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


## Compatibility with pwntools sockets

Pwn4Sage 的 `remote`、`listen`、`server` 已按 [pwntools 文档](https://docs.pwntools.com/en/latest/tubes/sockets.html#) 对齐，实现了以下特性：

- `remote(host, port, *, fam='any', typ='tcp'|'udp', sock=None, ssl=False, ssl_context=None, ssl_args=None, sni=True, timeout=None)`
  - 支持 IPv4/IPv6、TCP/UDP 两种套接字类型。
  - 可通过 `remote.fromsocket()` 包装已有 `socket.socket`。
  - TLS 连接遵循文档语义：默认 TLSv1.2，上层可指定 `ssl_context`/`ssl_args`/`sni`。
- `listen(port=0, bindaddr='::', fam='any', typ='tcp'|'udp', backlog=128)`
  - 监听 IPv4/IPv6，`bindaddr`、`fam` 参数与 pwntools 相同。
  - UDP 场景下 `wait_for_connection()` 会返回与首个客户端绑定的 tube，后续即可使用 `send`/`recv`。
- `server(port=0, bindaddr='::', fam='any', typ='tcp'|'udp', callback=None, blocking=False, backlog=128)`
  - 提供 callback 与 `next_connection()` 两种处理模式，兼容 pwntools 的辅助服务器语义。

测试可以通过 `pytest -q` 运行，包含 TCP/UDP/IPv4/IPv6/TLS 等回环用例，保证行为与 pwntools 一致。

### 进阶能力一览

- **日志/观测**
  - DEBUG 模式自动启用 hexdump、彩色标签、交互全量日志（可通过 `context.interactive_log` 设为 `'off'|'tags'|'full'`）。
  - `context.log_stream`、`context.log_file` 控制日志输出位置，`context.wiretap`/`tube.wiretap()` 可以镜像原始流量。
  - `tube.stats()/reset_stats()/peek()` 快速查看 send/recv 统计与缓冲区内容。
- **发送/接收细节**
  - `context.consume_delim_newline` 切换 `sendafter`/`sendlineafter` 的“严格匹配”与“提示+换行”兼容模式。
  - `process(..., tty=True)` 提供最小 PTY 支持，可直接与需要终端语义的程序交互。
  - `remote.fromsocket()` 支持将已有 `socket.socket` 包装成 Tube，方便在自定义环境中复用。
- **SSH 轻量封装**
  - `ssh(user=..., host=..., keyfile=...)` 基于系统 `ssh`，支持 `__call__`、`__getitem__`、`__getattr__` 运行命令，`shell()/system()/process()/remote()` 等行为贴近 pwntools。
  - `upload_data()` / `download_data()` 可快速在本地与远端间复制数据。
- **命令行参数魔法**
  - 解析 `PWNLIB_DEBUG=1`、`python exploit.py DEBUG TIMEOUT=10` 等写法，结果统一暴露在 `args[...]`，并自动联动 `context.log_level`、`context.timeout` 等设置。

更多示例可参考文档以及项目自带测试（`tests/test_pwn_full.py`）中的完整用例集合。
