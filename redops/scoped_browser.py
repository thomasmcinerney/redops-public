"""Direct Chromium capture through a single-target SOCKS5 proxy.

The browser can load arbitrary subresources chosen by the target page. The
proxy resolves no names and connects only to the assigned target IP, rejecting
every other destination before a socket is opened.
"""

import os
import select
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
from pathlib import Path


def _read_exact(conn, size):
    data = b''
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError('SOCKS client closed')
        data += chunk
    return data


class _ScopedSocksHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        client.settimeout(10)
        try:
            version, count = _read_exact(client, 2)
            methods = _read_exact(client, count)
            if version != 5 or 0 not in methods:
                client.sendall(b'\x05\xff')
                return
            client.sendall(b'\x05\x00')
            version, command, _, atyp = _read_exact(client, 4)
            if version != 5 or command != 1:
                client.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            if atyp == 1:
                host = socket.inet_ntop(socket.AF_INET, _read_exact(client, 4))
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, _read_exact(client, 16))
            elif atyp == 3:
                host = _read_exact(client, _read_exact(client, 1)[0]).decode('ascii')
            else:
                return
            port = int.from_bytes(_read_exact(client, 2), 'big')
            host = host.lower().rstrip('.')
            if host not in self.server.allowed_hosts:
                with self.server.records_lock:
                    self.server.blocked.append(f'{host}:{port}')
                client.sendall(b'\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            try:
                upstream = socket.create_connection((self.server.target_ip, port), timeout=10)
            except OSError:
                client.sendall(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            with upstream:
                with self.server.records_lock:
                    self.server.allowed.append(f'{host}:{port}')
                client.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                client.settimeout(None)
                upstream.settimeout(None)
                while True:
                    ready, _, _ = select.select((client, upstream), (), (), 30)
                    if not ready:
                        return
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        (upstream if source is client else client).sendall(data)
        except (OSError, UnicodeError, ConnectionError):
            return


class _ScopedSocksServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def _chromium(url: str, output: Path, width: int, height: int,
              timeout: int, network_flags: list[str]) -> tuple[str, str]:
    with tempfile.TemporaryDirectory(prefix='redops-browser-') as profile:
        command = [
            'chromium', '--headless=new', '--no-sandbox', '--disable-gpu',
            '--disable-dev-shm-usage', '--disable-extensions',
            '--disable-background-networking', '--disable-sync',
            '--disable-quic', '--no-first-run', '--no-default-browser-check',
            '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
            '--ignore-certificate-errors', *network_flags,
            f'--user-data-dir={profile}', f'--window-size={width},{height}',
            '--virtual-time-budget=6000', f'--screenshot={output}', url,
        ]
        proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True,
                                start_new_session=True)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.communicate()
            raise TimeoutError(f'Chromium screenshot exceeded {timeout}s')
    if proc.returncode != 0 or not output.is_file():
        raise RuntimeError(f'Chromium screenshot failed (exit {proc.returncode}): '
                           f'{stderr[-1000:]}')
    return stdout, stderr


def capture(url: str, target_ip: str, allowed_host: str, output: Path,
            width: int = 1280, height: int = 900, timeout: int = 45) -> dict:
    """Render one live URL and return proxy connection evidence."""
    with _ScopedSocksServer(('127.0.0.1', 0), _ScopedSocksHandler) as proxy:
        proxy.target_ip = target_ip
        proxy.allowed_hosts = {target_ip.lower(), allowed_host.lower().rstrip('.')}
        proxy.allowed = []
        proxy.blocked = []
        proxy.records_lock = threading.Lock()
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        stdout, stderr = _chromium(url, output, width, height, timeout, [
            '--proxy-bypass-list=<-loopback>',
            f'--proxy-server=socks5://127.0.0.1:{proxy.server_address[1]}',
            '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1',
        ])
        proxy.shutdown()
        return {'browser_exit': 0, 'connection_mode': 'guard_on_target_proxy',
                'allowed_connections': list(proxy.allowed),
                'blocked_connections': list(proxy.blocked),
                'browser_stdout': stdout, 'browser_stderr': stderr}


def capture_unrestricted(url: str, output: Path, width: int = 1280,
                         height: int = 900, timeout: int = 45) -> dict:
    """Render the assigned page with normal resources when scope_guard is off."""
    stdout, stderr = _chromium(url, output, width, height, timeout,
                               ['--no-proxy-server'])
    return {'browser_exit': 0, 'connection_mode': 'guard_off_direct',
            'allowed_connections': [], 'blocked_connections': [],
            'browser_stdout': stdout, 'browser_stderr': stderr}
