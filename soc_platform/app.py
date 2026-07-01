"""
SOC Alert Investigation Training Platform
Flask Backend - Main Application
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from datetime import datetime, timedelta
import sqlite3
import json
import hashlib
import os
import random

app = Flask(__name__)
app.secret_key = os.urandom(24)

DATABASE = 'soc_platform.db'

# ─────────────────────────────────────────────
# DATABASE HELPERS
# ─────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def query_db(query, args=(), one=False):
    conn = get_db()
    cur = conn.execute(query, args)
    rv = cur.fetchall()
    conn.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    conn = get_db()
    cur = conn.execute(query, args)
    conn.commit()
    last_id = cur.lastrowid
    conn.close()
    return last_id

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ─────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────

@app.route('/', methods=['GET'])
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        hashed = hash_password(password)
        user = query_db('SELECT * FROM users WHERE username=? AND password=?', [username, hashed], one=True)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            execute_db('UPDATE users SET last_login=? WHERE id=?', [datetime.now().isoformat(), user['id']])
            return redirect(url_for('dashboard'))
        flash('Invalid credentials. Try analyst / soc2024', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    uid = session['user_id']
    stats = {
        'total_alerts': query_db('SELECT COUNT(*) as c FROM alerts', one=True)['c'],
        'open_alerts': query_db("SELECT COUNT(*) as c FROM alerts WHERE status='open'", one=True)['c'],
        'critical_alerts': query_db("SELECT COUNT(*) as c FROM alerts WHERE severity='critical'", one=True)['c'],
        'completed': query_db("SELECT COUNT(*) as c FROM investigations WHERE analyst_id=? AND status='completed'", [uid], one=True)['c'],
        'score': query_db('SELECT COALESCE(SUM(score),0) as s FROM investigations WHERE analyst_id=?', [uid], one=True)['s'],
    }
    recent_alerts = query_db("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 8")
    recent_inv = query_db("""
        SELECT i.*, a.title, a.severity, a.category FROM investigations i
        JOIN alerts a ON i.alert_id=a.id
        WHERE i.analyst_id=? ORDER BY i.updated_at DESC LIMIT 5
    """, [uid])
    category_counts = query_db("""
        SELECT category, COUNT(*) as cnt FROM alerts GROUP BY category ORDER BY cnt DESC
    """)
    return render_template('dashboard.html', stats=stats, recent_alerts=recent_alerts,
                           recent_inv=recent_inv, category_counts=category_counts)

# ─────────────────────────────────────────────
# ALERT LIBRARY
# ─────────────────────────────────────────────

@app.route('/alerts')
@login_required
def alert_library():
    category = request.args.get('category', '')
    severity = request.args.get('severity', '')
    search = request.args.get('search', '')
    page = int(request.args.get('page', 1))
    per_page = 20

    query = "SELECT * FROM alerts WHERE 1=1"
    args = []
    if category:
        query += " AND category=?"
        args.append(category)
    if severity:
        query += " AND severity=?"
        args.append(severity)
    if search:
        query += " AND (title LIKE ? OR description LIKE ?)"
        args += [f'%{search}%', f'%{search}%']

    total = query_db(f"SELECT COUNT(*) as c FROM ({query})", args, one=True)['c']
    query += f" ORDER BY created_at DESC LIMIT {per_page} OFFSET {(page-1)*per_page}"
    alerts = query_db(query, args)

    categories = query_db("SELECT DISTINCT category FROM alerts ORDER BY category")
    uid = session['user_id']
    investigated = {r['alert_id'] for r in query_db("SELECT alert_id FROM investigations WHERE analyst_id=?", [uid])}

    return render_template('alerts.html', alerts=alerts, categories=categories,
                           category=category, severity=severity, search=search,
                           page=page, total=total, per_page=per_page,
                           investigated=investigated)

# ─────────────────────────────────────────────
# INVESTIGATION PAGE
# ─────────────────────────────────────────────

@app.route('/investigate/<int:alert_id>')
@login_required
def investigate(alert_id):
    alert = query_db('SELECT * FROM alerts WHERE id=?', [alert_id], one=True)
    if not alert:
        flash('Alert not found', 'error')
        return redirect(url_for('alert_library'))

    uid = session['user_id']
    inv = query_db('SELECT * FROM investigations WHERE alert_id=? AND analyst_id=?', [alert_id, uid], one=True)
    if not inv:
        inv_id = execute_db(
            "INSERT INTO investigations (alert_id, analyst_id, status, started_at, updated_at) VALUES (?,?,?,?,?)",
            [alert_id, uid, 'in_progress', datetime.now().isoformat(), datetime.now().isoformat()]
        )
        inv = query_db('SELECT * FROM investigations WHERE id=?', [inv_id], one=True)

    logs = query_db('SELECT * FROM logs WHERE alert_id=? ORDER BY timestamp', [alert_id])
    iocs = query_db('SELECT * FROM iocs WHERE alert_id=?', [alert_id])
    timeline = query_db('SELECT * FROM timeline WHERE alert_id=? ORDER BY event_time', [alert_id])

    # Parse JSON fields safely
    alert_dict = dict(alert)
    for field in ['host_info', 'user_info', 'mitre_mapping']:
        try:
            alert_dict[field] = json.loads(alert_dict.get(field) or '{}')
        except Exception:
            alert_dict[field] = {}

    return render_template('investigate.html', alert=alert_dict, inv=inv,
                           logs=logs, iocs=iocs, timeline=timeline)

# ─────────────────────────────────────────────
# LOG VIEWER
# ─────────────────────────────────────────────

@app.route('/logs')
@login_required
def log_viewer():
    alert_id = request.args.get('alert_id', '')
    ip_filter = request.args.get('ip', '')
    user_filter = request.args.get('user', '')
    event_id = request.args.get('event_id', '')
    log_type = request.args.get('log_type', '')
    search = request.args.get('search', '')

    query = "SELECT l.*, a.title as alert_title FROM logs l JOIN alerts a ON l.alert_id=a.id WHERE 1=1"
    args = []
    if alert_id:
        query += " AND l.alert_id=?"; args.append(alert_id)
    if ip_filter:
        query += " AND l.source_ip LIKE ?"; args.append(f'%{ip_filter}%')
    if user_filter:
        query += " AND l.username LIKE ?"; args.append(f'%{user_filter}%')
    if event_id:
        query += " AND l.event_id=?"; args.append(event_id)
    if log_type:
        query += " AND l.log_type=?"; args.append(log_type)
    if search:
        query += " AND l.raw_log LIKE ?"; args.append(f'%{search}%')

    query += " ORDER BY l.timestamp DESC LIMIT 200"
    logs = query_db(query, args)
    alerts_list = query_db("SELECT id, title FROM alerts ORDER BY title")
    log_types = query_db("SELECT DISTINCT log_type FROM logs ORDER BY log_type")

    return render_template('logs.html', logs=logs, alerts_list=alerts_list,
                           log_types=log_types, alert_id=alert_id,
                           ip_filter=ip_filter, user_filter=user_filter,
                           event_id=event_id, log_type=log_type, search=search)

# ─────────────────────────────────────────────
# SUBMIT INVESTIGATION
# ─────────────────────────────────────────────

@app.route('/submit_investigation', methods=['POST'])
@login_required
def submit_investigation():
    data = request.get_json()
    inv_id = data.get('inv_id')
    verdict = data.get('verdict')       # true_positive / false_positive / escalated
    notes = data.get('notes', '')
    ioc_confirmed = data.get('ioc_confirmed', [])

    uid = session['user_id']
    inv = query_db('SELECT i.*, a.expected_verdict, a.points FROM investigations i JOIN alerts a ON i.alert_id=a.id WHERE i.id=? AND i.analyst_id=?', [inv_id, uid], one=True)

    if not inv:
        return jsonify({'success': False, 'message': 'Investigation not found'})

    if inv['status'] == 'completed':
        return jsonify({'success': False, 'message': 'Already submitted'})

    correct = verdict == inv['expected_verdict']
    score = inv['points'] if correct else max(0, inv['points'] // 2)

    execute_db("""
        UPDATE investigations SET status='completed', verdict=?, analyst_notes=?,
        ioc_confirmed=?, score=?, completed_at=?, updated_at=?
        WHERE id=?
    """, [verdict, notes, json.dumps(ioc_confirmed), score,
          datetime.now().isoformat(), datetime.now().isoformat(), inv_id])

    execute_db('UPDATE alerts SET status=? WHERE id=?',
               ['closed' if correct else 'open', inv['alert_id']])

    return jsonify({
        'success': True,
        'correct': correct,
        'score': score,
        'expected': inv['expected_verdict'],
        'message': '✅ Correct! Well done, Analyst.' if correct else f'❌ Incorrect. Expected: {inv["expected_verdict"]}'
    })

# ─────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────

@app.route('/report/<int:inv_id>')
@login_required
def report(inv_id):
    uid = session['user_id']
    inv = query_db("""
        SELECT i.*, a.title, a.description, a.severity, a.category,
               a.host_info, a.user_info, a.mitre_mapping, a.expected_verdict
        FROM investigations i JOIN alerts a ON i.alert_id=a.id
        WHERE i.id=? AND i.analyst_id=?
    """, [inv_id, uid], one=True)

    if not inv:
        flash('Report not found', 'error')
        return redirect(url_for('dashboard'))

    iocs = query_db('SELECT * FROM iocs WHERE alert_id=?', [inv['alert_id']])
    timeline = query_db('SELECT * FROM timeline WHERE alert_id=? ORDER BY event_time', [inv['alert_id']])

    inv_dict = dict(inv)
    for field in ['host_info', 'user_info', 'mitre_mapping']:
        try:
            inv_dict[field] = json.loads(inv_dict.get(field) or '{}')
        except Exception:
            inv_dict[field] = {}

    return render_template('report.html', inv=inv_dict, iocs=iocs, timeline=timeline,
                           report_date=datetime.now().strftime('%Y-%m-%d %H:%M UTC'))

# ─────────────────────────────────────────────
# LEADERBOARD
# ─────────────────────────────────────────────

@app.route('/leaderboard')
@login_required
def leaderboard():
    board = query_db("""
        SELECT u.username, u.avatar_color, u.badge,
               COUNT(i.id) as completed,
               COALESCE(SUM(i.score), 0) as total_score,
               COALESCE(AVG(CASE WHEN i.verdict=a.expected_verdict THEN 100 ELSE 0 END), 0) as accuracy
        FROM users u
        LEFT JOIN investigations i ON i.analyst_id=u.id AND i.status='completed'
        LEFT JOIN alerts a ON i.alert_id=a.id
        GROUP BY u.id ORDER BY total_score DESC LIMIT 20
    """)
    uid = session['user_id']
    my_rank = None
    for idx, row in enumerate(board, 1):
        if row['username'] == session['username']:
            my_rank = idx
    return render_template('leaderboard.html', board=board, my_rank=my_rank)

# ─────────────────────────────────────────────
# API ENDPOINTS
# ─────────────────────────────────────────────

@app.route('/api/save_notes', methods=['POST'])
@login_required
def save_notes():
    data = request.get_json()
    execute_db('UPDATE investigations SET analyst_notes=?, updated_at=? WHERE id=? AND analyst_id=?',
               [data.get('notes'), datetime.now().isoformat(), data.get('inv_id'), session['user_id']])
    return jsonify({'success': True})

@app.route('/api/alert_stats')
@login_required
def alert_stats():
    categories = query_db("SELECT category, COUNT(*) as cnt FROM alerts GROUP BY category")
    severity = query_db("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity")
    return jsonify({
        'categories': [dict(r) for r in categories],
        'severity': [dict(r) for r in severity]
    })

@app.route('/api/profile')
@login_required
def profile():
    uid = session['user_id']
    user = query_db('SELECT * FROM users WHERE id=?', [uid], one=True)
    stats = query_db("""
        SELECT COUNT(*) as total, SUM(score) as score,
               SUM(CASE WHEN verdict=a.expected_verdict THEN 1 ELSE 0 END) as correct
        FROM investigations i JOIN alerts a ON i.alert_id=a.id
        WHERE i.analyst_id=? AND i.status='completed'
    """, [uid], one=True)
    return jsonify({'user': dict(user), 'stats': dict(stats)})

# ─────────────────────────────────────────────
# DB INIT
# ─────────────────────────────────────────────

def init_db():
    from data.seed import seed_database
    conn = get_db()
    with open('schema.sql', 'r') as f:
        conn.executescript(f.read())
    conn.close()
    seed_database()
    print("✅ Database initialized and seeded.")

if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True, port=5000)
