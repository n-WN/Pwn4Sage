# Assume pwn4sage.py is loaded or imported as shown previously
# Example: from pwn4sage import *
from pwn7 import *

# Challenge details
HOST = "91a99798c0e6f1a7f0584083-1024-intro-crypto-1.challenge.cscg.live"
PORT = 1337

print(f"Connecting to {HOST}:{PORT} using SSL with verification...")

# Set log level (adjust as needed)
# context.set_log_level("debug")  # For detailed SSL info
context.set_log_level("debug")   # For less output
# context.set_log_level("critical") # Minimal output

try:
    # Create the remote connection using SSL
    # use_ssl=True:  Enables SSL/TLS wrapping.
    # ssl_check_hostname=True (Default): Equivalent to --ssl-verify, verifies the hostname.
    # server_hostname=HOST (Default): Ensures SNI is used correctly.
    io = remote(
        host=HOST,
        port=PORT,
        use_ssl=True,
        # The following are defaults but explicitly shown for clarity matching --ssl-verify:
        ssl_check_hostname=True,
        server_hostname=HOST
    )

    print("Connection successful!")
    print("Switching to interactive mode...")
    print("--- INTERACTIVE SESSION START (Ctrl+C to exit) ---")

    # Interact with the server
    io.interactive()

    print("\n--- INTERACTIVE SESSION ENDED ---")

except (ConnectionError, TimeoutError, OSError, ssl.SSLError) as e:
    print(f"\n[ERROR] Connection failed: {e}")
    # If it's an SSL verification error, provide a hint
    if isinstance(e, ssl.SSLCertVerificationError) or "certificate verify failed" in str(e).lower():
        print("[HINT] Certificate verification failed.")
        print("[HINT] If this is expected (e.g., self-signed cert), you might need:")
        print(f"[HINT]   io = remote('{HOST}', {PORT}, use_ssl=True, ssl_check_hostname=False)")
    elif isinstance(e, ssl.SSLError):
         print("[HINT] An SSL error occurred during connection or handshake.")
except Exception as e:
    print(f"\n[ERROR] An unexpected error occurred: {e}")