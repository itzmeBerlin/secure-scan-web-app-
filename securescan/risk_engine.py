"""
risk_engine.py — Classifies vulnerabilities as Critical / High / Medium / Low / Info
based on open ports, service versions, and missing security headers.
"""
from attack_intel import get_attack_intel

# ─── Known dangerous service/version patterns ─────────────────────────────────
# Format: (regex_pattern, risk_level, description, recommendation)

PORT_RISK_DB = {
    21:   ('High',     'FTP is unencrypted and often exploited.',     'Disable FTP; use SFTP/SCP instead.'),
    22:   ('Low',      'SSH is generally secure but should be hardened.', 'Disable root login, use key-based auth.'),
    23:   ('Critical', 'Telnet sends credentials in plaintext.',       'Disable Telnet immediately; use SSH.'),
    25:   ('High',     'SMTP may be an open relay.',                  'Restrict to authenticated users only.'),
    53:   ('Medium',   'DNS service exposed.',                        'Restrict recursive queries, enable DNSSEC.'),
    80:   ('Low',      'HTTP traffic is unencrypted.',                'Redirect all traffic to HTTPS.'),
    110:  ('High',     'POP3 sends credentials in plaintext.',        'Use POP3S or migrate to IMAPS.'),
    135:  ('Critical', 'RPC service, commonly exploited on Windows.', 'Restrict to internal network, apply patches.'),
    139:  ('Critical', 'NetBIOS — legacy Windows file sharing.',      'Disable if not needed, block on firewall.'),
    443:  ('Info',     'HTTPS — check certificate validity.',         'Ensure TLS 1.2+ and strong cipher suites.'),
    445:  ('Critical', 'SMB — frequently exploited (EternalBlue).',  'Patch immediately. Block externally.'),
    1433: ('Critical', 'MSSQL exposed to network.',                  'Restrict to localhost or VPN only.'),
    1521: ('Critical', 'Oracle DB exposed to network.',              'Restrict to localhost or VPN only.'),
    3306: ('High',     'MySQL/MariaDB exposed.',                     'Bind to 127.0.0.1, use strong credentials.'),
    3389: ('Critical', 'RDP — brute-force and exploit target.',      'Restrict to VPN, use NLA, keep patched.'),
    5432: ('High',     'PostgreSQL exposed.',                        'Bind to localhost, restrict with pg_hba.conf.'),
    5900: ('High',     'VNC — often has weak/no authentication.',    'Use VPN + strong password or disable.'),
    6379: ('Critical', 'Redis exposed without authentication.',      'Bind to localhost, set requirepass.'),
    8080: ('Medium',   'HTTP Proxy / dev server exposed.',           'Do not expose staging servers publicly.'),
    8443: ('Medium',   'Alternate HTTPS port exposed.',              'Restrict access, check for default creds.'),
    9200: ('Critical', 'Elasticsearch exposed — data leak risk.',   'Bind to localhost, enable security plugin.'),
    27017:('Critical', 'MongoDB exposed without auth.',              'Enable auth, bind to localhost.'),
}

RISKY_VERSIONS = [
    ('vsftpd 2.3.4', 'Critical', 'vsftpd 2.3.4 contains a backdoor (CVE-2011-2523).'),
    ('OpenSSH 7.4',  'High',     'OpenSSH < 7.6 has user enumeration vulnerability (CVE-2018-15473).'),
    ('Apache/2.4.29','High',     'Apache 2.4.29 has known CVEs — upgrade to 2.4.58+.'),
    ('Apache/2.2',   'Critical', 'Apache 2.2 is End-of-Life. Multiple critical vulnerabilities.'),
    ('nginx/1.14',   'Medium',   'nginx 1.14 has known vulnerabilities — upgrade to 1.24+.'),
    ('PHP/5',        'Critical', 'PHP 5.x is End-of-Life. Extremely vulnerable.'),
    ('MySQL 5.7',    'Medium',   'MySQL 5.7 EOL Jan 2023. Consider upgrading to 8.x.'),
    ('Microsoft-IIS/7', 'High',  'IIS 7 is End-of-Life. Multiple known vulnerabilities.'),
]

HEADER_RISKS = {
    'Strict-Transport-Security': ('High',   'Missing HSTS allows downgrade attacks.'),
    'Content-Security-Policy':   ('High',   'Missing CSP enables XSS attacks.'),
    'X-Frame-Options':           ('Medium', 'Missing X-Frame-Options enables clickjacking.'),
    'X-Content-Type-Options':    ('Low',    'Missing X-Content-Type-Options allows MIME sniffing.'),
    'X-XSS-Protection':          ('Low',    'Missing legacy XSS protection header.'),
    'Referrer-Policy':           ('Low',    'Missing Referrer-Policy leaks URL in referrer.'),
    'Permissions-Policy':        ('Low',    'Missing Permissions-Policy exposes browser features.'),
}

RISK_ORDER = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
RISK_COLORS = {
    'Critical': '#ff2d55',
    'High':     '#ff6b35',
    'Medium':   '#ffd60a',
    'Low':      '#34c759',
    'Info':     '#5ac8fa',
}


def analyze_risks(nmap_data: dict, curl_data: dict) -> dict:
    findings = []
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}

    # ── Port-based risks ──────────────────────────────────────────────────────
    for port_info in nmap_data.get('ports', []):
        if port_info['state'] != 'open':
            continue

        port_num = port_info['port']
        version  = port_info.get('version', '') or ''
        service  = port_info.get('service', '')

        # Check port risk DB
        if port_num in PORT_RISK_DB:
            risk, desc, rec = PORT_RISK_DB[port_num]
            entry = {
                'type': 'port',
                'port': port_num,
                'service': service,
                'severity': risk,
                'color': RISK_COLORS[risk],
                'title': f'Port {port_num} ({service}) Open',
                'description': desc,
                'recommendation': rec,
                'cve': None,
            }
            entry['attack'] = get_attack_intel(entry)
            findings.append(entry)
            severity_counts[risk] += 1

        # Check version-based risks
        for pattern, risk, desc in RISKY_VERSIONS:
            if pattern.lower() in version.lower() or pattern.lower() in service.lower():
                entry = {
                    'type': 'version',
                    'port': port_num,
                    'service': service,
                    'severity': risk,
                    'color': RISK_COLORS[risk],
                    'title': f'Vulnerable Version: {pattern}',
                    'description': desc,
                    'recommendation': 'Update to the latest stable version immediately.',
                    'cve': None,
                }
                entry['attack'] = get_attack_intel(entry)
                findings.append(entry)
                severity_counts[risk] += 1

    # ── Header-based risks ────────────────────────────────────────────────────
    for missing_header in curl_data.get('security_headers_missing', []):
        if missing_header in HEADER_RISKS:
            risk, desc = HEADER_RISKS[missing_header]
            entry = {
                'type': 'header',
                'port': None,
                'service': 'HTTP/HTTPS',
                'severity': risk,
                'color': RISK_COLORS[risk],
                'title': f'Missing Security Header: {missing_header}',
                'description': desc,
                'recommendation': f'Add the "{missing_header}" HTTP response header on your web server.',
                'cve': None,
            }
            entry['attack'] = get_attack_intel(entry)
            findings.append(entry)
            severity_counts[risk] += 1

    # ── Sort by severity ──────────────────────────────────────────────────────
    findings.sort(key=lambda x: RISK_ORDER.get(x['severity'], 0), reverse=True)

    # ── Overall risk score (0–100) ────────────────────────────────────────────
    score = min(100, (
        severity_counts['Critical'] * 30 +
        severity_counts['High']     * 15 +
        severity_counts['Medium']   * 7  +
        severity_counts['Low']      * 2
    ))
    if   score >= 70: overall = 'Critical'
    elif score >= 50: overall = 'High'
    elif score >= 30: overall = 'Medium'
    elif score > 0:   overall = 'Low'
    else:             overall = 'Info'

    return {
        'findings': findings,
        'summary':  severity_counts,
        'risk_score': score,
        'overall_risk': overall,
        'overall_color': RISK_COLORS[overall],
        'total_findings': len(findings),
    }
