#!/usr/bin/env python3
import subprocess
import threading
import time
import sys
import os
import select

# --- Configuration ---
NC_PORT = 12345
CLIENT_SCRIPT = "test_.py"
# Data nc should send back AFTER receiving "payload\n"
NC_RESPONSE_DATA = b"123\n123prompt>\nEOF\nEOF!\n"
# String nc prints when it receives data (adjust if your nc behaves differently)
# We'll wait for the client's *first* output line before sending from nc
# A simpler trigger: wait for nc to print the received payload
NC_RECEIVE_TRIGGER = b"payload" # nc usually prints the received data (without newline)

# Timeout for the whole operation
OVERALL_TIMEOUT_SEC = 20 # Increased timeout to allow for setup and execution

# --- Globals ---
print_lock = threading.Lock()
stop_logging = threading.Event()
payload_received_event = threading.Event()

# --- Helper Functions ---
def get_timestamp():
    """Returns a formatted timestamp string."""
    return time.strftime("%Y-%m-%d %H:%M:%S") + f".{int(time.time()*1000)%1000:03d}"

def log_message(name, message):
    """Prints a message with timestamp and process name, thread-safely."""
    with print_lock:
        timestamp = get_timestamp()
        for line in message.strip().splitlines(): # Handle multi-line messages
             print(f"[{timestamp}] [{name}] {line}", flush=True)

def stream_logger(name, stream):
    """Target function for logging threads."""
    try:
        # Use select for non-blocking read attempt on the stream's fileno
        fileno = stream.fileno()
        while not stop_logging.is_set():
            # Wait up to 0.1 seconds for data
            readable, _, _ = select.select([fileno], [], [], 0.1)
            if fileno in readable:
                line = stream.readline() # Read available data
                if not line: # EOF
                    log_message(name, "<EOF - Stream Closed>")
                    break
                # Log raw bytes first for debug
                # log_message(name + "_BYTES", f"{line!r}")
                try:
                    decoded_line = line.decode('utf-8', errors='replace').strip()
                    log_message(name, decoded_line)

                    # --- Trigger Logic ---
                    # Check if nc received the payload
                    if name == "NC_STDOUT" and NC_RECEIVE_TRIGGER in line:
                        log_message("DIAG", f"Detected trigger '{NC_RECEIVE_TRIGGER!r}' in NC output.")
                        payload_received_event.set() # Signal that nc received payload

                except Exception as e:
                    log_message(name, f"<Error decoding line: {e}> Raw: {line!r}")
            # If select times out, loop continues and checks stop_logging flag
    except ValueError:
        log_message(name, "<Stream FD closed unexpectedly>")
    except Exception as e:
        log_message(name, f"<Error in logger thread: {e}>")
    finally:
        log_message(name, "<Logger thread finished>")
        # Ensure the stream is closed from this end if Popen didn't handle it
        try:
             stream.close()
        except Exception:
            pass


# --- Main Execution ---
nc_proc = None
client_proc = None
threads = []

try:
    # 1. Start nc server
    nc_command = ["nc", "-lvp", str(NC_PORT)]
    log_message("DIAG", f"Starting server: {' '.join(nc_command)}")
    nc_proc = subprocess.Popen(
        nc_command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        # bufsize=1, # Line buffering
        # universal_newlines=False # Work with bytes
    )
    log_message("DIAG", f"Server process started (PID: {nc_proc.pid})")

    # Give nc a moment to start listening (crude, better to check output)
    # time.sleep(0.5) # Replaced with output checking

    # Start logging threads for nc
    t_nc_out = threading.Thread(target=stream_logger, args=("NC_STDOUT", nc_proc.stdout), daemon=True)
    t_nc_err = threading.Thread(target=stream_logger, args=("NC_STDERR", nc_proc.stderr), daemon=True)
    threads.extend([t_nc_out, t_nc_err])
    t_nc_out.start()
    t_nc_err.start()

    # Wait until nc confirms it's listening or trigger is seen (some nc versions differ)
    log_message("DIAG", "Waiting for server to be ready (or receive payload)...")
    # We now wait for the "payload" trigger via the event, which implies nc is ready and connected to
    payload_received_event.wait(timeout=1) # Wait max 10s for client to connect and send
    # fix: wait 1s 

    if not payload_received_event.is_set():
         # Check nc stderr for common 'Listening' message if payload wasn't received quickly
         # This part is tricky as nc output varies. The payload trigger is more reliable *after* client starts.
         log_message("DIAG", "Server might not be ready or client didn't send payload yet.")
         # For now, proceed assuming nc might be ready even without explicit msg

    # 2. Start the client script
    client_command = [sys.executable, CLIENT_SCRIPT] # Use the same python interpreter
    log_message("DIAG", f"Starting client: {' '.join(client_command)}")
    client_proc = subprocess.Popen(
        client_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        # bufsize=1,
        # universal_newlines=False # Let client script handle its encoding
    )
    log_message("DIAG", f"Client process started (PID: {client_proc.pid})")

    # Start logging threads for client
    t_client_out = threading.Thread(target=stream_logger, args=("CLIENT_STDOUT", client_proc.stdout), daemon=True)
    t_client_err = threading.Thread(target=stream_logger, args=("CLIENT_STDERR", client_proc.stderr), daemon=True)
    threads.extend([t_client_out, t_client_err])
    t_client_out.start()
    t_client_err.start()

    # 3. Wait for the trigger indicating nc received the payload
    log_message("DIAG", f"Waiting for trigger: NC receiving '{NC_RECEIVE_TRIGGER!r}'...")
    triggered = payload_received_event.wait(timeout=10) # Wait up to 10 seconds

    if triggered:
        log_message("DIAG", f"Trigger received! Sending response data to NC's stdin.")
        try:
            nc_proc.stdin.write(NC_RESPONSE_DATA)
            nc_proc.stdin.flush()
            log_message("DIAG", f"Data sent to NC: {NC_RESPONSE_DATA!r}")
            nc_proc.stdin.close() # Signal EOF to nc's input
            log_message("DIAG", "Closed NC stdin.")
        except (BrokenPipeError, OSError) as e:
             log_message("DIAG", f"Error writing to NC stdin (maybe it closed?): {e}")
    else:
        log_message("DIAG", "Timeout waiting for NC to receive payload trigger. NC might not have received 'payload'.")


    # 4. Wait for the client process to complete
    log_message("DIAG", f"Waiting for client process ({client_proc.pid}) to finish...")
    try:
        client_proc.wait(timeout=OVERALL_TIMEOUT_SEC) # Wait for client with overall timeout
        log_message("DIAG", f"Client process finished. Exit code: {client_proc.returncode}")
    except subprocess.TimeoutExpired:
        log_message("DIAG", f"Client process timed out after {OVERALL_TIMEOUT_SEC} seconds. Terminating.")
        client_proc.terminate()
        try:
            client_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            log_message("DIAG", "Client process did not terminate gracefully. Killing.")
            client_proc.kill()
        log_message("DIAG", f"Client process terminated/killed. Exit code: {client_proc.returncode}")

except Exception as e:
    log_message("DIAG", f"An error occurred in the main script: {e}")
    import traceback
    log_message("DIAG", traceback.format_exc())

finally:
    log_message("DIAG", "--- Cleanup ---")
    stop_logging.set() # Signal logging threads to stop

    # Terminate processes if they are still running
    if client_proc and client_proc.poll() is None:
        log_message("DIAG", f"Terminating client process ({client_proc.pid})...")
        client_proc.terminate()
        time.sleep(0.1)
        if client_proc.poll() is None:
            client_proc.kill()
            log_message("DIAG", f"Killed client process ({client_proc.pid}).")


    if nc_proc and nc_proc.poll() is None:
        log_message("DIAG", f"Terminating server process ({nc_proc.pid})...")
        # Closing stdin might be enough for nc, but terminate is safer
        try:
             if not nc_proc.stdin.closed:
                 nc_proc.stdin.close()
        except Exception:
             pass
        nc_proc.terminate()
        time.sleep(0.1)
        if nc_proc.poll() is None:
            nc_proc.kill()
            log_message("DIAG", f"Killed server process ({nc_proc.pid}).")


    log_message("DIAG", "Waiting for logger threads to finish...")
    # Wait briefly for threads to finish after signaling stop
    main_thread = threading.current_thread()
    for t in threads:
         if t is not main_thread: # Don't join self
             t.join(timeout=1.0) # Wait max 1 second per thread
             if t.is_alive():
                  log_message("DIAG", f"Logger thread {t.name} did not finish cleanly.")

    # Final check on process exit codes
    if nc_proc:
         log_message("DIAG", f"Final NC exit code: {nc_proc.poll()}")
    if client_proc:
         log_message("DIAG", f"Final Client exit code: {client_proc.poll()}")

    log_message("DIAG", "Diagnostic script finished.")