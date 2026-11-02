"""An actual Chromium capture reaches only the assigned synthetic server."""

import http.server
import importlib
import json
import socket
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'report-kit'))
import report

server = importlib.import_module('redops.mcp_server')
browser = importlib.import_module('redops.scoped_browser')


@pytest.fixture
def web_server():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/redirect':
                self.send_response(302)
                self.send_header('Location', 'http://198.51.100.99:12345/outside')
                self.end_headers()
                return
            body = (b'<html><title>Assigned target</title><body>Direct page'
                    b'<img src="http://198.51.100.99:12345/pixel"></body></html>')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    app = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=app.serve_forever, daemon=True)
    thread.start()
    try:
        yield app.server_address[1]
    finally:
        app.shutdown()
        app.server_close()


def test_chromium_screenshot_proxy_blocks_offscope_subresource(tmp_path, monkeypatch,
                                                               web_server):
    original = socket.create_connection

    def route(address, *args, **kwargs):
        if address[0] == '192.0.2.10':
            return original(('127.0.0.1', address[1]), *args, **kwargs)
        return original(address, *args, **kwargs)

    monkeypatch.setattr(browser.socket, 'create_connection', route)
    output = tmp_path / 'shot.png'
    result = browser.capture(f'http://192.0.2.10:{web_server}/',
                             '192.0.2.10', '192.0.2.10', output, timeout=25)
    assert output.is_file() and output.stat().st_size > 1000
    assert any(item.startswith('192.0.2.10:') for item in result['allowed_connections'])
    assert any(item.startswith('198.51.100.99:') for item in result['blocked_connections'])


def test_chromium_proxy_blocks_offscope_redirect(tmp_path, monkeypatch,
                                                   web_server):
    original = socket.create_connection

    def route(address, *args, **kwargs):
        if address[0] == '192.0.2.10':
            return original(('127.0.0.1', address[1]), *args, **kwargs)
        return original(address, *args, **kwargs)

    monkeypatch.setattr(browser.socket, 'create_connection', route)
    output = tmp_path / 'redirect.png'
    result = browser.capture(f'http://192.0.2.10:{web_server}/redirect',
                             '192.0.2.10', '192.0.2.10', output, timeout=25)
    assert any(item.startswith('192.0.2.10:') for item in result['allowed_connections'])
    assert '198.51.100.99:12345' in result['blocked_connections']


def test_chromium_proxy_maps_explicit_vhost_to_assigned_ip(tmp_path,
                                                            monkeypatch,
                                                            web_server):
    original = socket.create_connection

    def route(address, *args, **kwargs):
        if address[0] == '192.0.2.10':
            return original(('127.0.0.1', address[1]), *args, **kwargs)
        return original(address, *args, **kwargs)

    monkeypatch.setattr(browser.socket, 'create_connection', route)
    output = tmp_path / 'vhost.png'
    result = browser.capture(f'http://assigned.example:{web_server}/',
                             '192.0.2.10', 'assigned.example', output, timeout=25)
    assert output.is_file()
    assert any(item.startswith('assigned.example:')
               for item in result['allowed_connections'])


def test_mcp_browser_rejects_unassigned_or_outside_allowlist(tmp_path, monkeypatch):
    monkeypatch.setattr(server, '__file__', str(tmp_path / 'redops' / 'mcp_server.py'))
    monkeypatch.setattr(server, '_engagement', lambda: 7)
    monkeypatch.setattr(server, 'find_target',
                        lambda ip: {'id': 1, 'ip': ip} if ip == '192.0.2.10'
                        else (_ for _ in ()).throw(ValueError('unassigned')))
    def guarded(method, path):
        if path == '/api/settings':
            return {'scope_guard': {'value': True}}
        return {'in': ['192.0.2.10/32'], 'out': []}
    monkeypatch.setattr(server, 'req', guarded)
    server.report_case_init('Practice', '192.0.2.10 only')
    server.report_target_add('box', 'Assigned box', '192.0.2.10', 'web',
                           'Document page', 'In progress', unscored=True)
    server.report_stage_add('box', 'recon', 'Initial recon')
    with pytest.raises(ValueError, match='explicit vhost'):
        server.report_browser_screenshot('box', 'recon',
                                       'http://198.51.100.99/', 'No')
    monkeypatch.setattr(server, 'req',
                        lambda method, path: {'scope_guard': {'value': True}}
                        if path == '/api/settings'
                        else {'in': ['198.51.100.99/32'], 'out': []})
    with pytest.raises(ValueError, match='outside the engagement allowlist'):
        server.report_browser_screenshot('box', 'recon',
                                       'http://192.0.2.10/', 'No')

    monkeypatch.setattr(server, 'req', guarded)
    def blocked_capture(url, ip, host, output):
        from PIL import Image
        Image.new('RGB', (32, 24), 'white').save(output)
        return {'connection_mode': 'guard_on_target_proxy',
                'allowed_connections': ['192.0.2.10:80'],
                'blocked_connections': ['198.51.100.99:443'],
                'browser_stdout': '', 'browser_stderr': ''}
    monkeypatch.setattr(browser, 'capture', blocked_capture)
    with pytest.raises(ValueError, match='screenshot was not attached'):
        server.report_browser_screenshot('box', 'recon',
                                       'http://192.0.2.10/', 'Blocked page')
    case = report.load(tmp_path / 'data' / 'work' / '7' / 'report-case')
    assert not any(event['kind'] == 'screenshot' for event in case['events'])


def test_mcp_proof_keeps_full_value(tmp_path, monkeypatch):
    monkeypatch.setattr(server, '__file__', str(tmp_path / 'redops' / 'mcp_server.py'))
    monkeypatch.setattr(server, '_engagement', lambda: 7)
    monkeypatch.setattr(server, 'find_target', lambda ip: {'id': 1, 'ip': ip})
    server.report_case_init('Practice', '192.0.2.10 only')
    server.report_target_add('box', 'Assigned box', '192.0.2.10', 'web',
                           'Document proof', 'In progress', unscored=True,
                           required_stages='proof')
    server.report_stage_add('box', 'proof', 'Proof')
    value = 'copy-paste-this-complete-value-å'
    result = json.loads(server.report_proof_set('box', '/proof.txt', value))
    assert result['proof_sha256'] == report.text_sha256(value)
    case = report.load(tmp_path / 'data' / 'work' / '7' / 'report-case')
    assert case['targets']['box']['proof']['value'] == value


def test_mcp_browser_attaches_direct_capture(tmp_path, monkeypatch):
    monkeypatch.setattr(server, '__file__', str(tmp_path / 'redops' / 'mcp_server.py'))
    monkeypatch.setattr(server, '_engagement', lambda: 7)
    monkeypatch.setattr(server, 'find_target', lambda ip: {'id': 1, 'ip': ip})
    monkeypatch.setattr(server, 'req',
                        lambda method, path: {'scope_guard': {'value': False}})
    feed = []
    monkeypatch.setattr(server, 'log',
                        lambda text, kind, target_ip: feed.append((text, kind, target_ip)))
    server.report_case_init('Practice', '192.0.2.10 only')
    server.report_target_add('box', 'Assigned box', '192.0.2.10', 'web',
                           'Document page', 'In progress', unscored=True)
    server.report_stage_add('box', 'recon', 'Initial recon')

    def direct_capture(url, output):
        from PIL import Image
        Image.new('RGB', (64, 48), 'blue').save(output)
        return {'connection_mode': 'guard_off_direct',
                'allowed_connections': [], 'blocked_connections': [],
                'browser_stdout': 'page rendered', 'browser_stderr': ''}

    monkeypatch.setattr(browser, 'capture_unrestricted', direct_capture)
    result = json.loads(server.report_browser_screenshot(
        'box', 'recon', 'http://192.0.2.10/', 'Observed target page'))
    root = tmp_path / 'data' / 'work' / '7' / 'report-case'
    case = report.load(root)
    shot = next(event for event in case['events']
                if event['id'] == result['screenshot_id'])
    assert shot['provenance'] == 'direct_import'
    assert report.is_direct_capture(root, shot)
    assert any(event['kind'] == 'browser' for event in case['events'])
    assert result['connection_mode'] == 'guard_off_direct'
    assert feed and feed[0][1:] == ('action', '192.0.2.10')
