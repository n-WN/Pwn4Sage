from pwn7 import remote, log, context, p32, u32, ssl
import sys

context.set_log_level('debug') # or 'info'

# ... your exploit logic ...
# ssl
# ssl.ssl_context = True
# conn = remote('91a99798c0e6f1a7f0584083-1024-intro-crypto-1.challenge.cscg.live', 1337)
# conn = remote('tcpbin.com', 4242)
conn = remote(
    '127.0.0.1',
    12345,
)
conn.sendline(b'payload')
# data = conn.recvuntil(b'prompt>')  # Adjust the prompt as needed
# print(data)

# data = conn.recvall()  # EOF
# print(data)
data = conn.recvuntil(b'prompt>')
# --- FIX: Print to stderr AGAIN ---
print(data, file=sys.stderr, flush=True)
# --- END FIX ---

data = conn.recvall()  # EOF
# --- FIX: Print to stderr AGAIN ---
print(data, file=sys.stderr, flush=True)
# --- END FIX ---

conn.interactive()
conn.close()