# я добавил все требования в незнайка/requirements.txt
# напишы pip install -r requirements.txt в терминали 
from flask import Flask, render_template, request, jsonify, session, abort
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import bleach
import re
import os
import hashlib
import time
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(32)

# CSRF
csrf = CSRFProtect(app)

# Rate Limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100 per hour", "20 per minute"]
)

# Security
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Database
def init_db():
    conn = sqlite3.connect('feedback.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            ip_hash TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    #rate limiting at DB level
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS submission_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_hash TEXT NOT NULL,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# Anti-XSS
def sanitize_input(text, max_length=1000):
    if text is None:
        return ""
    # Strip HTML 
    cleaned = bleach.clean(str(text), tags=[], strip=True)
    cleaned = cleaned.replace('\x00', '')
    # Limit length
    return cleaned[:max_length].strip() 

# Validate 
def validate_score(score, min_val=0, max_val=10):
    try:
        score = int(score)
        if min_val <= score <= max_val:
            return score
    except (ValueError, TypeError):
        pass
    return None

# Hash IP
def hash_ip(ip):
    return hashlib.sha256(ip.encode()).hexdigest()[:16]

# Check honeypot 
def check_honeypots(form_data):
    honeypot_fields = ['website', 'email_confirm', 'phone_number']
    for field in honeypot_fields:
        if form_data.get(field):
            return False  # Bot detected
    return True

# Check submission timing 
def check_submission_time(form_data):
    try:
        form_timestamp = float(form_data.get('form_load_time', 0))
        current_time = time.time()
        elapsed = current_time - form_timestamp
        if elapsed < 3:
            return False
    except (ValueError, TypeError):
        return False
    return True

# Check for spam 
def check_spam_patterns(text):
    if not text:
        return True
    spam_patterns = [
        r'http[s]?://', 
        r'\[url=', 
        r'<a\s+href',
        r'gambling|site|like', # наверное убери это, это проверка на спам 
        r'(.)\1{10,}',
    ]
    for pattern in spam_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return False
    return True


def check_db_rate_limit(ip_hash, max_submissions=5, window_minutes=60):
    conn = sqlite3.connect('feedback.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT COUNT(*) FROM submission_log 
        WHERE ip_hash = ? AND submitted_at > datetime('now', ?)
    ''', (ip_hash, f'-{window_minutes} minutes'))
    count = cursor.fetchone()[0]
    conn.close()
    return count < max_submissions

def log_submission(ip_hash):
    conn = sqlite3.connect('feedback.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO submission_log (ip_hash) VALUES (?)', (ip_hash,))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    form_load_time = time.time()
    return render_template('form.html', form_load_time=form_load_time)

@app.route('/submit', methods=['POST'])
@limiter.limit("5 per minute")
def submit():
    try:
        # Get IP hash 
        ip_hash = hash_ip(request.remote_addr or 'unknown')  
        if not check_db_rate_limit(ip_hash):
            return jsonify({
                'success': False, 
                'message': 'Слишком много запросов. Попробуйте позже.'
            }), 429
        # Check honeypots
        if not check_honeypots(request.form):
            return jsonify({'success': True, 'message': 'Спс за отзыв!'})
        
        # Check submission timing
        if not check_submission_time(request.form):
            return jsonify({'success': True, 'message': 'Спс за отзыв'})
        
        name = sanitize_input(request.form.get('name'), 200)
        role = sanitize_input(request.form.get('role'), 200)
        
        if not all([name, role]):
            return jsonify({
                'success': False, 
                'message': 'Пожалуйста, заполните все обязательные поля.'
            }), 400

        if not check_spam_patterns(name) or not check_spam_patterns(role):
            return jsonify({
                'success': False, 
                'message': 'Обнаружен подозрительный контент.'
            }), 400
        

        conn = sqlite3.connect('feedback.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO feedback (name, role, ip_hash, user_agent)
            VALUES (?, ?, ?, ?)
        ''', (
            name, role, ip_hash,
            sanitize_input(request.headers.get('User-Agent', ''), 500)
        ))
        conn.commit()
        conn.close()
        

        log_submission(ip_hash)
        
        return jsonify({
            'success': True, 
            'message': 'Спасибо за ваш отзыв! Мы ценим ваше мнение.'
        })
        
    except Exception as e:
        app.logger.error(f"Submission error: {str(e)}")
        return jsonify({
            'success': False, 
            'message': 'Произошла ошибка. Попробуйте позже.'
        }), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=False, host='127.0.0.1', port=5000)


