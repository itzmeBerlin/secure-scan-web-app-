"""
scanner.py — Wraps nmap and curl into structured, JSON-serializable Python dicts.
On Windows (dev), returns realistic mock data so you can build the UI without Kali.
On Kali Linux (production), runs the real tools.
"""

import subprocess
import platform
import re
import json
import datetime
import time


IS_LINUX = platform.system() == 'Linux'

# ─────────────────────────────────────────────────────────────────────────────
# NMAP
# ─────────────────────────────────────────────────────────────────────────────

SCAN_FLAGS = {
    'quick':   ['-sV', '--top-ports', '100', '-T5', '--min-rate', '1000', '--max-retries', '1'],
    'full':    ['-sV', '-sC', '-p-', '-T5', '--min-rate', '1000', '--max-retries', '2'],
    'stealth': ['-sS', '-sV', '--top-ports', '100', '-T4', '--min-rate', '500'],
}

def run_nmap_scan(target: str, scan_type: str = 'quick', log_cb=None, scan_id=None) -> dict:
    """Run nmap and return structured results."""
    if IS_LINUX:
        return _run_real_nmap(target, scan_type, log_cb, scan_id)
    else:
        return _mock_nmap(target, log_cb, scan_id)


def _run_real_nmap(target, scan_type, socketio, scan_id):
    flags = SCAN_FLAGS.get(scan_type, SCAN_FLAGS['quick'])
    cmd = ['nmap'] + flags + [target]
    ports = []
    raw_lines = []

    # Regex is evaluated a lot; precompile once.
    port_line_re = re.compile(r'(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?')

    # Throttle scan_log websocket emissions to avoid slowing down the scan.
    # Tune these if you want more/less live output.
    emit_every_n_lines = 10
    emit_min_interval_s = 0.25

    last_emit_ts = 0.0
    line_count_since_last_emit = 0

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        for line in process.stdout:
            line = line.rstrip()
            raw_lines.append(line)

            line_count_since_last_emit += 1

            # Emit live log line via callback (throttled)
            if log_cb:
                now = time.time()
                if (
                    line_count_since_last_emit >= emit_every_n_lines
                    or (now - last_emit_ts) >= emit_min_interval_s
                ):
                    log_cb(line)
                    last_emit_ts = now
                    line_count_since_last_emit = 0

            # Parse port lines: "80/tcp   open  http    Apache httpd 2.4.41"
            match = port_line_re.match(line)
            if match:
                ports.append({
                    'port': int(match.group(1)),
                    'protocol': match.group(2),
                    'state': match.group(3),
                    'service': match.group(4),
                    'version': (match.group(5) or '').strip(),
                })

        process.wait()
    except FileNotFoundError:
        return {'error': 'nmap not found. Install with: sudo apt install nmap', 'ports': []}


    return {
        'target': target,
        'scan_type': scan_type,
        'ports': ports,
        'raw': '\n'.join(raw_lines),
        'timestamp': datetime.datetime.now().isoformat(),
    }


def _mock_nmap(target, log_cb=None, scan_id=None):
    """Realistic mock data for development on non-Linux systems."""
    if log_cb:
        log_cb(f'Starting Arcane Matrix scan on {target}...')
        time.sleep(1.0)
        log_cb('Scanning top 100 ports...')
        time.sleep(1.5)
        log_cb('Discovered open port 22/tcp')
        log_cb('Discovered open port 80/tcp')
        log_cb('Discovered open port 443/tcp')
        time.sleep(1.5)
        log_cb('Service detection completed.')
        time.sleep(0.5)

    return {
        'target': target,
        'scan_type': 'quick (mock)',
        'ports': [
            {'port': 22,   'protocol': 'tcp', 'state': 'open', 'service': 'ssh',   'version': 'OpenSSH 7.4'},
            {'port': 80,   'protocol': 'tcp', 'state': 'open', 'service': 'http',  'version': 'Apache httpd 2.4.29'},
            {'port': 443,  'protocol': 'tcp', 'state': 'open', 'service': 'https', 'version': 'nginx 1.14.0'},
            {'port': 21,   'protocol': 'tcp', 'state': 'open', 'service': 'ftp',   'version': 'vsftpd 2.3.4'},
            {'port': 3306, 'protocol': 'tcp', 'state': 'open', 'service': 'mysql', 'version': 'MySQL 5.7.28'},
            {'port': 8080, 'protocol': 'tcp', 'state': 'open', 'service': 'http-proxy', 'version': ''},
            {'port': 3389, 'protocol': 'tcp', 'state': 'open', 'service': 'ms-wbt-server', 'version': 'Microsoft Terminal Services'},
        ],
        'raw': 'Mock data - run on Kali Linux for real results',
        'timestamp': datetime.datetime.now().isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# CURL / HTTP HEADER ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'X-XSS-Protection',
    'Referrer-Policy',
    'Permissions-Policy',
]

def run_curl_scan(target: str) -> dict:
    """Fetch HTTP headers and analyse security posture."""
    # Make sure target has a scheme
    if not target.startswith(('http://', 'https://')):
        url = f'http://{target}'
    else:
        url = target

    if IS_LINUX:
        return _run_real_curl(url)
    else:
        return _mock_curl(url)


def _run_real_curl(url):
    cmd = ['curl', '-sI', '--max-time', '10', '--location', url]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        headers_raw = result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        headers_raw = ''

    headers = {}
    for line in headers_raw.splitlines():
        if ':' in line:
            key, _, value = line.partition(':')
            headers[key.strip()] = value.strip()

    present = [h for h in SECURITY_HEADERS if h.lower() in {k.lower() for k in headers}]
    missing = [h for h in SECURITY_HEADERS if h not in present]

    return {
        'url': url,
        'headers': headers,
        'security_headers_present': present,
        'security_headers_missing': missing,
        'server': headers.get('Server', 'Unknown'),
    }


def _mock_curl(url):
    return {
        'url': url,
        'headers': {
            'Server': 'Apache/2.4.29 (Ubuntu)',
            'X-Frame-Options': 'SAMEORIGIN',
            'X-Content-Type-Options': 'nosniff',
            'Content-Type': 'text/html; charset=UTF-8',
        },
        'security_headers_present': ['X-Frame-Options', 'X-Content-Type-Options'],
        'security_headers_missing': ['Strict-Transport-Security', 'Content-Security-Policy', 'X-XSS-Protection', 'Referrer-Policy', 'Permissions-Policy'],
        'server': 'Apache/2.4.29 (Ubuntu)',
    }
