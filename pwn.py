#!/usr/bin/env python3
# _*_ coding: utf-8 _*_
import socket
import select
import sys
import time # Import time module for potential timeouts
import subprocess
import os
import threading
import fcntl

class context:
    """Global context settings for Pwn4Sage."""
    log_level = "info"

    @staticmethod
    def set_log_level(level):
        """Sets the global logging level."""
        context.log_level = level

def log(message, level="info", length=None, interactive_mode=False, is_input=False):
    """Logs messages to the console with specified level and formatting."""
    log_levels = {
        "debug": 10,
        "info": 20,
        "warning": 30,
        "error": 40
    }
    # Default to info level if context.log_level is invalid
    current_log_level = log_levels.get(context.log_level, 20)
    message_log_level = log_levels.get(level, 20)

    if message_log_level < current_log_level:
        return  # Do not print messages below the current log level

    colors = {
        "info": "\033[94m",
        "debug": "\033[92m",
        "warning": "\033[93m",
        "error": "\033[91m",
        "input": "\033[95m",  # Color for sent data
        "output": "\033[96m" # Color for received data
    }
    reset = "\033[0m"

    # Determine action and color based on whether it's input or output
    action = "Sent" if is_input else "Received"
    action_color = colors.get('input' if is_input else 'output', '')

    # Prepare the log prefix based on mode and level
    level_tag = f"{colors.get(level, '')}[{level.upper()}]{reset}"
    if interactive_mode:
        mode_prefix = "[IN]" if is_input else "[OUT]"
        mode_color = colors.get('input' if is_input else 'output', '')
        colored_mode_prefix = f"{mode_color}{mode_prefix}{reset}"
        log_prefix = f"{level_tag} {colored_mode_prefix} {action_color}{action}{reset}"
    else:
        log_prefix = f"{level_tag} {action_color}{action}{reset}"

    # Decode bytes to string for printing, replacing errors
    if isinstance(message, bytes):
        try:
            # Try decoding with utf-8, replace errors
            printable_message = message.decode('utf-8', errors='replace')
        except UnicodeDecodeError:
            # Fallback for non-utf8 data
            printable_message = repr(message)
    else:
        printable_message = str(message) # Ensure message is string

    # Print formatted message
    if length is not None:
        print(f"{log_prefix} {length} bytes:")
        # Indent message lines for clarity
        for line in printable_message.splitlines():
            print(f"    {line}")
    else:
        # Print non-length messages directly
        for line in printable_message.splitlines():
            print(f"{log_prefix} {line}")


class remote:
    """Represents a remote connection."""
    def __init__(self, host, port, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        """Initializes the connection to the remote host."""
        self.host = host
        self.port = port
        self.sh = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sh.settimeout(timeout) # Set socket timeout
        self._buffer = b'' # Internal buffer for recvuntil
        try:
            self.sh.connect((host, port))
            log(f"Opened connection to {host} on port {port}", "info")
        except socket.error as e:
            log(f"Connection refused: {host}:{port} - {e}", "error")
            raise # Re-raise the exception

    def __enter__(self):
        """Enter the runtime context related to this object."""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Exit the runtime context related to this object."""
        self.close()

    def send(self, msg: bytes):
        """Sends raw bytes to the remote host."""
        assert isinstance(msg, bytes), "Message must be bytes"
        try:
            self.sh.sendall(msg) # Use sendall for reliability
            log(msg, "debug", len(msg), is_input=True)
        except socket.error as e:
            log(f"Error sending data: {e}", "error")
            self.close()
            raise

    def sendline(self, msg: bytes):
        """Sends bytes followed by a newline character."""
        self.send(msg + b'\n')

    def recv(self, num: int = 4096):
        """Receives up to 'num' bytes from the remote host."""
        try:
            data = self.sh.recv(num)
            if not data:
                log("Connection closed by remote host", "info")
                self.close() # Ensure socket is closed on empty read
                return b''
            log(data, "debug", len(data), is_input=False)
            return data
        except socket.timeout:
            log("Socket timeout during recv", "warning")
            return b''
        except socket.error as e:
            log(f"Error receiving data: {e}", "error")
            self.close()
            raise

    def recvuntil(self, delim: bytes, drop: bool = False):
        """Receives data until the delimiter 'delim' is found."""
        assert isinstance(delim, bytes), "Delimiter must be bytes"
        start_time = time.time()
        while delim not in self._buffer:
            # Check for timeout if one is set
            if self.sh.gettimeout() is not None:
                elapsed = time.time() - start_time
                if elapsed > self.sh.gettimeout():
                    log("Timeout waiting for delimiter", "warning")
                    # Return what we have, maybe partial match
                    data_to_return = self._buffer
                    self._buffer = b''
                    log(data_to_return, "debug", len(data_to_return), is_input=False)
                    return data_to_return # Or raise TimeoutError?

            try:
                chunk = self.sh.recv(4096)
                if not chunk:
                    log("Connection closed while waiting for delimiter", "info")
                    self.close()
                    # Return whatever is left in buffer
                    data_to_return = self._buffer
                    self._buffer = b''
                    log(data_to_return, "debug", len(data_to_return), is_input=False)
                    return data_to_return # Or raise EOFError?
                self._buffer += chunk
            except socket.timeout:
                # This might happen if timeout is very short, let the outer loop handle overall timeout
                continue
            except socket.error as e:
                log(f"Socket error during recvuntil: {e}", "error")
                self.close()
                raise

        # Delimiter found
        delim_index = self._buffer.find(delim)
        # Include delimiter in the result
        data_to_return = self._buffer[:delim_index + len(delim)]
        # Update buffer: keep the part after the delimiter
        self._buffer = self._buffer[delim_index + len(delim):]

        if drop:
            # If drop is True, don't include the delimiter itself
            data_to_return = data_to_return[:-len(delim)]

        log(data_to_return, "debug", len(data_to_return), is_input=False)
        return data_to_return

    def recvline(self, drop: bool = True):
        """Receives data until a newline character is found."""
        return self.recvuntil(b'\n', drop=drop)

    def recvline_contains(self, keyword: bytes, drop: bool = True):
        """Receives lines until one containing the keyword is found."""
        assert isinstance(keyword, bytes), "Keyword must be bytes"
        while True:
            line = self.recvline(drop=False) # Keep newline for check
            if not line: # Handle EOF or timeout
                return b''
            if keyword in line:
                if drop:
                    return line.rstrip(b'\n') # Remove trailing newline if dropping
                else:
                    return line

    def sendafter(self, delim: bytes, msg: bytes):
        """Receives data until 'delim' is found, then sends 'msg'."""
        assert isinstance(delim, bytes) and isinstance(msg, bytes)
        received_data = self.recvuntil(delim)
        self.send(msg)
        return received_data # Return the data received before sending

    def close(self):
        """Closes the connection."""
        if self.sh:
            try:
                self.sh.shutdown(socket.SHUT_RDWR) # Gracefully shutdown
            except socket.error:
                pass # Ignore errors on shutdown (e.g., socket already closed)
            self.sh.close()
            self.sh = None # Mark as closed
            log("Connection closed", "info")

    def interactive(self):
        """Enters interactive mode, forwarding data between stdin/stdout and the socket."""
        log("Switched to interactive mode", "warning") # Use log function
        try:
            while self.sh: # Check if socket is still open
                # Wait for readiness on socket or stdin, with a small timeout
                readable, _, _ = select.select([self.sh, sys.stdin], [], [], 0.1)

                if self.sh in readable:
                    try:
                        data = self.sh.recv(4096)
                        if not data:
                            log("Connection closed by remote host", "info")
                            break # Exit loop if connection closed
                        # Print received data directly to stdout
                        sys.stdout.buffer.write(data)
                        sys.stdout.buffer.flush()
                        # Log received data at debug level if enabled
                        log(data, "debug", len(data), interactive_mode=True, is_input=False)
                    except socket.error as e:
                        log(f"Socket error during interactive recv: {e}", "error")
                        break # Exit on error

                if sys.stdin in readable:
                    try:
                        # Read directly from stdin buffer
                        input_data = sys.stdin.buffer.readline()
                        if not input_data: # Handle EOF from stdin (e.g., Ctrl+D)
                            log("EOF received from stdin, closing connection.", "info")
                            break
                        self.send(input_data) # Send data including newline
                        # Log sent data at debug level if enabled
                        # log(input_data, "debug", len(input_data), interactive_mode=True, is_input=True) # Already logged in send()
                    except EOFError:
                        log("EOFError reading from stdin, closing connection.", "info")
                        break # Exit loop on EOF
                    except Exception as e: # Catch other potential stdin errors
                         log(f"Error reading from stdin: {e}", "error")
                         break

        except KeyboardInterrupt:
            log("Interactive session ended by user (KeyboardInterrupt)", "info")
        except Exception as e:
            log(f"An unexpected error occurred in interactive mode: {e}", "error")
        finally:
            self.close() # Ensure connection is closed on exit

class process:
    """Represents a local process interaction."""
    def __init__(self, argv, executable=None, cwd=None, env=None, timeout=None):
        """Initializes and starts the local process."""
        if executable is None:
            executable = argv[0]

        # Ensure executable path is absolute or find it in PATH
        if not os.path.isabs(executable) and '/' not in executable:
            # Simplified PATH search
            paths = os.environ.get('PATH', '').split(os.pathsep)
            found = False
            for path in paths:
                full_path = os.path.join(path, executable)
                if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                    executable = full_path
                    found = True
                    break
            if not found:
                raise FileNotFoundError(f"Executable '{executable}' not found in PATH.")
        elif not os.path.isfile(executable) or not os.access(executable, os.X_OK):
             raise FileNotFoundError(f"Executable '{executable}' not found or not executable.")


        self.argv = argv
        self.executable = executable
        self.cwd = cwd
        self.env = env if env else os.environ.copy() # Use current env if not specified
        self._buffer = b''
        self.timeout = timeout # Store timeout for potential use in recv

        try:
            self.proc = subprocess.Popen(
                self.argv,
                executable=self.executable,
                cwd=self.cwd,
                env=self.env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, # Redirect stderr to stdout for simplicity
                bufsize=0 # Unbuffered
            )
            log(f"Started process '{' '.join(argv)}' (PID: {self.proc.pid})", "info")

            # Make stdout non-blocking
            fd = self.proc.stdout.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        except Exception as e:
            log(f"Failed to start process: {e}", "error")
            raise

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def send(self, msg: bytes):
        """Sends raw bytes to the process's stdin."""
        assert isinstance(msg, bytes), "Message must be bytes"
        if not self.proc or self.proc.stdin.closed:
            log("Process stdin is closed, cannot send.", "warning")
            return
        try:
            self.proc.stdin.write(msg)
            self.proc.stdin.flush()
            log(msg, "debug", len(msg), is_input=True)
        except OSError as e: # Catch BrokenPipeError etc.
            log(f"Error sending data to process: {e}", "error")
            self.close() # Close on error
            raise

    def sendline(self, msg: bytes):
        """Sends bytes followed by a newline character."""
        self.send(msg + b'\n')

    def _read_stdout_non_blocking(self, num=4096):
        """Internal helper to read non-blockingly from stdout."""
        if not self.proc or self.proc.stdout.closed:
            return b''
        try:
            return self.proc.stdout.read(num)
        except (BlockingIOError, InterruptedError):
            return b'' # No data available right now
        except OSError as e:
            log(f"Error reading from process stdout: {e}", "error")
            self.close()
            return b'' # Treat as EOF on error

    def recv(self, num: int = 4096, timeout=None):
        """Receives up to 'num' bytes from the process's stdout."""
        if self._buffer:
            data = self._buffer[:num]
            self._buffer = self._buffer[num:]
            log(data, "debug", len(data), is_input=False)
            return data

        # Use the provided timeout or the instance default
        current_timeout = timeout if timeout is not None else self.timeout
        start_time = time.time()

        while True:
            data = self._read_stdout_non_blocking(num)
            if data:
                log(data, "debug", len(data), is_input=False)
                return data

            # Check if process exited
            if self.proc.poll() is not None:
                 log("Process exited while waiting for data.", "info")
                 remaining_data = self._read_stdout_non_blocking(num) # Try one last read
                 if remaining_data:
                     log(remaining_data, "debug", len(remaining_data), is_input=False)
                 return remaining_data # Return any last bit or b''

            # Check timeout
            if current_timeout is not None:
                elapsed = time.time() - start_time
                if elapsed >= current_timeout:
                    log("Timeout during recv", "warning")
                    return b''

            # Small sleep to prevent busy-waiting
            time.sleep(0.01)


    def recvuntil(self, delim: bytes, drop: bool = False, timeout=None):
        """Receives data until the delimiter 'delim' is found."""
        assert isinstance(delim, bytes), "Delimiter must be bytes"

        # Use the provided timeout or the instance default
        current_timeout = timeout if timeout is not None else self.timeout
        start_time = time.time()

        while delim not in self._buffer:
            # Check timeout
            if current_timeout is not None:
                elapsed = time.time() - start_time
                if elapsed >= current_timeout:
                    log(f"Timeout waiting for delimiter {delim!r}", "warning")
                    # Return what we have, even if incomplete
                    data_to_return = self._buffer
                    self._buffer = b''
                    log(data_to_return, "debug", len(data_to_return), is_input=False)
                    return data_to_return

            # Try reading more data
            chunk = self._read_stdout_non_blocking(4096)
            if chunk:
                self._buffer += chunk
            elif self.proc.poll() is not None and not self._buffer:
                 # Process exited and buffer is empty
                 log(f"Process exited before finding delimiter {delim!r}", "info")
                 return b'' # Return empty bytes as delimiter wasn't found
            elif not chunk:
                 # No data read, sleep briefly
                 time.sleep(0.01)


        # Delimiter found
        delim_index = self._buffer.find(delim)
        data_to_return = self._buffer[:delim_index + len(delim)]
        self._buffer = self._buffer[delim_index + len(delim):]

        if drop:
            data_to_return = data_to_return[:-len(delim)]

        log(data_to_return, "debug", len(data_to_return), is_input=False)
        return data_to_return

    def recvline(self, drop: bool = True, timeout=None):
        """Receives data until a newline character is found."""
        return self.recvuntil(b'\n', drop=drop, timeout=timeout)

    def interactive(self):
        """Enters interactive mode, forwarding data between stdin/stdout and the process."""
        log("Switched to interactive mode with process", "warning")

        # Flag to signal the reading thread to stop
        stop_reading = threading.Event()

        def reader_thread():
            while not stop_reading.is_set() and self.proc and self.proc.stdout:
                try:
                    # Use select for potentially better responsiveness than non-blocking read loop
                    readable, _, _ = select.select([self.proc.stdout], [], [], 0.1)
                    if self.proc.stdout in readable:
                        try:
                            # Read available data (might be less than 4096)
                            data = self.proc.stdout.read(4096)
                            if not data: # Pipe closed or process ended
                                log("Process stdout closed or process ended.", "info")
                                break
                            sys.stdout.buffer.write(data)
                            sys.stdout.buffer.flush()
                            log(data, "debug", len(data), interactive_mode=True, is_input=False)
                        except (OSError, ValueError) as e: # Catch errors like reading from closed pipe
                            log(f"Error reading from process stdout in interactive: {e}", "error")
                            break
                except Exception as e:
                    # Catch potential select errors or other issues
                    log(f"Error in reader thread: {e}", "error")
                    break # Exit thread on error
            log("Reader thread finished.", "debug")


        reader = threading.Thread(target=reader_thread, daemon=True)
        reader.start()

        try:
            while self.proc and self.proc.poll() is None: # Check if process is running
                # Use select to wait for stdin readiness
                readable, _, _ = select.select([sys.stdin], [], [], 0.1)
                if sys.stdin in readable:
                    try:
                        input_data = sys.stdin.buffer.readline()
                        if not input_data: # Handle EOF (Ctrl+D)
                            log("EOF received from stdin, closing process stdin.", "info")
                            self.proc.stdin.close() # Signal EOF to process
                            break # Exit interactive loop, let reader finish
                        self.send(input_data) # send logs internally
                    except EOFError:
                        log("EOFError reading from stdin, closing process stdin.", "info")
                        if self.proc and self.proc.stdin:
                             self.proc.stdin.close()
                        break
                    except (OSError, ValueError) as e: # Catch errors writing to closed pipe
                        log(f"Error writing to process stdin: {e}", "error")
                        break
                    except Exception as e:
                         log(f"Error reading from stdin: {e}", "error")
                         break

        except KeyboardInterrupt:
            log("Interactive session ended by user (KeyboardInterrupt)", "info")
        except Exception as e:
            log(f"An unexpected error occurred in interactive mode: {e}", "error")
        finally:
            log("Exiting interactive mode.", "info")
            stop_reading.set() # Signal reader thread to stop
            reader.join(timeout=1.0) # Wait briefly for reader thread
            self.close() # Ensure process is closed

    def close(self):
        """Closes the streams and terminates the process."""
        if not self.proc:
            return

        pid = self.proc.pid # Get PID before potentially closing streams

        # Close streams first
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
             if stream:
                 try:
                     stream.close()
                 except OSError:
                     pass # Ignore errors closing already closed streams

        # Terminate the process if it's still running
        if self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=0.5) # Wait briefly for termination
                log(f"Terminated process {pid}", "info")
            except subprocess.TimeoutExpired:
                log(f"Process {pid} did not terminate gracefully, killing.", "warning")
                self.proc.kill()
                self.proc.wait() # Wait for kill
                log(f"Killed process {pid}", "info")
            except Exception as e:
                log(f"Error terminating/killing process {pid}: {e}", "error")

        self.proc = None # Mark as closed
        log(f"Closed process {pid}", "info")

    def poll(self, block=False):
        """Check if the process has exited."""
        if not self.proc:
            return None # Or raise an error? Consistent with pwntools returning None
        if block:
            return self.proc.wait()
        else:
            return self.proc.poll()


if __name__ == "__main__":
    # Example Usage
    context.set_log_level("debug") # Set log level for detailed output

    # Using 'with' statement for automatic closing
    try:
        # Example with a public echo server (replace if needed)
        # Note: titan.picoctf.net might not be available or suitable for this test
        with remote("tcpbin.com", 4242) as r:
            print("--- Sending 'hello\n' ---")
            r.sendline(b"hello")

            print("--- Receiving line ---")
            line = r.recvline()
            print(f"Received line: {line!r}") # Use repr for clarity

            print("--- Sending 'world' after receiving 'hello\n' ---")
            # Note: tcpbin echoes, so we expect 'hello\n' back
            r.sendafter(b"hello\n", b"world\n")

            print("--- Receiving until 'world\n' ---")
            data = r.recvuntil(b"world\n")
            print(f"Received until: {data!r}")

            # Uncomment to test interactive mode (might require a different server)
            # print("--- Entering interactive mode (Ctrl+C or Ctrl+D to exit) ---")
            # r.interactive()

    except ConnectionRefusedError:
        print("Connection refused. Is the server running and accessible?")
    except Exception as e:
        print(f"An error occurred: {e}")

    print("\n--- Example without 'with' (manual close) ---")
    try:
        # Ensure this host/port is valid for testing
        r2 = remote("example.com", 80, timeout=5) # Connect to example.com HTTP port
        r2.sendline(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        response = r2.recvuntil(b"</html>") # Read until end of HTML tag
        print(f"Received {len(response)} bytes from example.com")
        r2.close()
    except Exception as e:
        print(f"An error occurred with r2: {e}")

    print("\n--- Example with local process ---")
    context.set_log_level("debug")
    try:
        # Example using 'cat'
        with process(['/bin/cat']) as p:
            print("--- Sending 'hello process\n' to cat ---")
            p.sendline(b"hello process")
            line = p.recvline()
            print(f"Received line from cat: {line!r}")

            print("--- Sending 'another line\n' ---")
            p.sendline(b"another line")
            line = p.recvuntil(b'line\n')
            print(f"Received until 'line\n': {line!r}")

            # Example using 'echo'
        with process(['/bin/echo', 'Test message']) as p_echo:
             output = p_echo.recvall() # Helper needed or recv until EOF
             print(f"Received from echo: {output!r}")


        # Uncomment to test interactive mode with a shell
        # print("--- Entering interactive mode with sh (type 'exit' to quit) ---")
        # with process(['/bin/sh']) as p_sh:
        #    p_sh.interactive()

    except FileNotFoundError as e:
        print(f"Error starting process: {e}. Is the executable path correct?")
    except Exception as e:
        print(f"An error occurred with process: {e}")

    # Add recvall helper function if needed, or instruct users to recv in a loop
    # def recvall(self, timeout=0.1):
    #     all_data = b''
    #     while True:
    #         data = self.recv(timeout=timeout)
    #         if not data:
    #             break
    #         all_data += data
    #     return all_data
    # process.recvall = recvall # Monkey-patch if desired
