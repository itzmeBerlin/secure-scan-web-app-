from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
from flask_socketio import SocketIO, emit
import threading
import json
import os
import sqlite3
import time
from functools import wraps
from scanner import run_nmap_scan, run_curl_scan
from risk_engine import analyze_risks
from report_gen import generate_pdf_report, generate_html_report

app = Flask(__name__)
app.config['SECRET_KEY'] = 'security-platform-secret-2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

REPORTS_DIR = os.path.join(os.path.dirname(__file__), 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)
DB_PATH = os.path.join(os.path.dirname(__file__), 'autoscan.db')

MASTER_PASSWORD = 'arcane'

# ─── DB Setup ─────────────────────────────────────────────────────────────────
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target TEXT,
                scan_type TEXT,
                timestamp TEXT,
                risk_score INTEGER,
                result_json TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                scan_type TEXT,
                interval_hours INTEGER,
                last_run TEXT
            )
        ''')
        conn.commit()

init_db()

# ─── Auth Decorator ───────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Authentication totally disabled
        return f(*args, **kwargs)
    return decorated_function

# ─── Global State for Polling ───────────────────────────────────────────────
ACTIVE_SCANS = {}

# ─── Auth ───────────────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Auto-login since auth is disabled
        session['authenticated'] = True
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

# ─── API ──────────────────────────────────────────────────────────────────────

@app.route('/api/scan', methods=['POST'])
@login_required
def api_scan():
    """Start a scan in the background and stream results via WebSocket."""
    data = request.get_json()
    target = data.get('target', '').strip()
    scan_type = data.get('scan_type', 'quick')  # quick | full | stealth
    schedule = data.get('schedule', False)

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    if schedule:
        # Save to schedules table
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO schedules (target, scan_type, interval_hours, last_run) VALUES (?, ?, ?, ?)',
                      (target, scan_type, 24, ''))
            conn.commit()
        return jsonify({'message': 'Scan scheduled successfully'})

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM scans")
        count = c.fetchone()[0]
    scan_id = f"scan_{count + 1:04d}"

    def background_scan():
        ACTIVE_SCANS[scan_id] = {'status': 'running', 'progress': 10, 'logs': [f'Starting {scan_type} scan on {target}...']}
        
        def log_cb(line):
            ACTIVE_SCANS[scan_id]['logs'].append(line)
            ACTIVE_SCANS[scan_id]['progress'] = min(ACTIVE_SCANS[scan_id]['progress'] + 5, 90)
            
        try:
            log_cb('Running Nmap port scan...')
            nmap_results = run_nmap_scan(target, scan_type, log_cb, scan_id)
            log_cb('Analyzing HTTP headers...')
            curl_results = run_curl_scan(target)
            log_cb('Running risk analysis engine...')
            risk_data = analyze_risks(nmap_results, curl_results)

            result = {
                'scan_id': scan_id,
                'target': target,
                'scan_type': scan_type,
                'nmap': nmap_results,
                'curl': curl_results,
                'risks': risk_data,
                'timestamp': __import__('datetime').datetime.now().isoformat()
            }

            with sqlite3.connect(DB_PATH) as conn:
                c = conn.cursor()
                c.execute('''INSERT INTO scans (scan_id, target, scan_type, timestamp, risk_score, result_json)
                             VALUES (?, ?, ?, ?, ?, ?)''', 
                          (scan_id, target, scan_type, result['timestamp'], risk_data.get('risk_score', 0), json.dumps(result)))
                conn.commit()

            result_file = os.path.join(REPORTS_DIR, f'{scan_id}.json')
            with open(result_file, 'w') as f:
                json.dump(result, f, indent=2)

            ACTIVE_SCANS[scan_id] = {'status': 'complete', 'result': result}

        except Exception as e:
            ACTIVE_SCANS[scan_id] = {'status': 'error', 'error': str(e)}

    # Start thread
    thread = threading.Thread(target=background_scan, daemon=True)
    thread.start()

    return jsonify({'scan_id': scan_id, 'message': 'Scan started'})


@app.route('/api/scan/status/<scan_id>')
@login_required
def api_scan_status(scan_id):
    """Poll for live scan status."""
    data = ACTIVE_SCANS.get(scan_id)
    if not data:
        return jsonify({'status': 'not_found'})
        
    # If running, pop logs so we don't resend them endlessly
    if data['status'] == 'running':
        logs = data.get('logs', [])
        data['logs'] = []
        return jsonify({
            'status': 'running',
            'progress': data['progress'],
            'logs': logs
        })
        
    return jsonify(data)

@app.route('/api/history')
@login_required
def api_history():
    """Return all past scan summaries from DB."""
    summaries = []
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT scan_id, target, timestamp, result_json FROM scans ORDER BY timestamp DESC")
        for row in c.fetchall():
            res = json.loads(row[3])
            risks = res.get('risks', {})
            summaries.append({
                'scan_id': row[0],
                'target': row[1],
                'timestamp': row[2],
                'risk_summary': risks.get('summary', {}),
                'risk_score': risks.get('risk_score', 0),
                'overall_risk': risks.get('overall_risk', 'Unknown')
            })
    return jsonify(summaries)


@app.route('/api/history', methods=['DELETE'])
@login_required
def api_clear_history():
    """Clear all past scan history."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("DELETE FROM scans")
            conn.commit()
            
        import glob
        for file in glob.glob(os.path.join(REPORTS_DIR, "*.json")):
            try:
                os.remove(file)
            except Exception:
                pass
                
        return jsonify({'message': 'History cleared successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/<scan_id>')
@login_required
def api_scan_result(scan_id):
    """Return full details of a specific scan."""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT result_json FROM scans WHERE scan_id = ?", (scan_id,))
        row = c.fetchone()
        if row:
            return jsonify(json.loads(row[0]))
    return jsonify({'error': 'Scan not found'}), 404


@app.route('/api/report/<scan_id>/pdf')
@login_required
def api_report_pdf(scan_id):
    result_file = os.path.join(REPORTS_DIR, f'{scan_id}.json')
    if not os.path.exists(result_file):
        return jsonify({'error': 'Scan not found'}), 404
    with open(result_file) as f:
        data = json.load(f)
    pdf_path = generate_pdf_report(data, REPORTS_DIR)
    return send_file(pdf_path, as_attachment=True, download_name=f'{scan_id}_report.pdf')


@app.route('/api/report/<scan_id>/html')
# @login_required
def api_report_html(scan_id):
    result_file = os.path.join(REPORTS_DIR, f'{scan_id}.json')
    if not os.path.exists(result_file):
        return jsonify({'error': 'Scan not found'}), 404
    with open(result_file) as f:
        data = json.load(f)
    html_path = generate_html_report(data, REPORTS_DIR)
    return send_file(html_path, as_attachment=True, download_name=f'{scan_id}_report.html')

@app.route('/api/report/<scan_id>/view')
# @login_required
def api_report_view(scan_id):
    result_file = os.path.join(REPORTS_DIR, f'{scan_id}.json')
    if not os.path.exists(result_file):
        return jsonify({'error': 'Scan not found'}), 404
    with open(result_file) as f:
        data = json.load(f)
    html_path = generate_html_report(data, REPORTS_DIR)
    return send_file(html_path)

@app.route('/api/report/<scan_id>/edit', methods=['POST'])
# @login_required
def api_report_edit(scan_id):
    payload = request.json
    result_file = os.path.join(REPORTS_DIR, f'{scan_id}.json')
    if not os.path.exists(result_file):
        return jsonify({'error': 'Scan not found'}), 404
        
    with open(result_file, 'r') as f:
        data = json.load(f)
        
    data['custom_exec_summary'] = payload.get('custom_exec_summary', '')
    data['custom_methodology'] = payload.get('custom_methodology', '')
    
    with open(result_file, 'w') as f:
        json.dump(data, f, indent=2)
        
    # Also update the database so the frontend `/api/scan/<scan_id>` gets it
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("UPDATE scans SET result_json = ? WHERE scan_id = ?", (json.dumps(data), scan_id))
        conn.commit()
        
    return jsonify({'success': True})

# ─── Watcher Daemon ───────────────────────────────────────────────────────────
def watcher_daemon():
    """Background thread to run scheduled scans."""
    while True:
        try:
            now_iso = __import__('datetime').datetime.now().isoformat()
            with sqlite3.connect(DB_PATH) as conn:
                c = conn.cursor()
                c.execute("SELECT id, target, scan_type, last_run, interval_hours FROM schedules")
                schedules = c.fetchall()
                
                for sched in schedules:
                    sid, target, scan_type, last_run, interval_hours = sched
                    if not last_run:
                        c.execute("UPDATE schedules SET last_run = ? WHERE id = ?", (now_iso, sid))
                        conn.commit()
                        
                        c.execute("SELECT COUNT(*) FROM scans")
                        count = c.fetchone()[0]
                        scan_id = f"scan_{count + 1:04d}"
                        
                        nmap_results = run_nmap_scan(target, scan_type)
                        curl_results = run_curl_scan(target)
                        risk_data = analyze_risks(nmap_results, curl_results)
                        result = {
                            'scan_id': scan_id, 'target': target, 'scan_type': scan_type,
                            'nmap': nmap_results, 'curl': curl_results, 'risks': risk_data,
                            'timestamp': __import__('datetime').datetime.now().isoformat()
                        }
                        c.execute('''INSERT INTO scans (scan_id, target, scan_type, timestamp, risk_score, result_json)
                                     VALUES (?, ?, ?, ?, ?, ?)''', 
                                  (scan_id, target, scan_type, result['timestamp'], risk_data.get('risk_score', 0), json.dumps(result)))
                        conn.commit()
                        
                        with open(os.path.join(REPORTS_DIR, f'{scan_id}.json'), 'w') as f:
                            json.dump(result, f, indent=2)
        except Exception as e:
            print("Watcher daemon error:", e)
        time.sleep(60) # check every minute

watcher_thread = threading.Thread(target=watcher_daemon, daemon=True)
watcher_thread.start()

# ─── Run ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
