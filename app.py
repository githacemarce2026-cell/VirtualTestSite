from flask import Flask, render_template, request, redirect, url_for, session, flash
import time

app = Flask(__name__)
app.secret_key = 'simple_secret_key'

MAX_REQUESTS = 5
TIME_WINDOW = 10

MAX_FAILED_LOGINS = 3
FAILED_LOGIN_WINDOW = 30

BLOCK_TIME = 30


request_history = {}
failed_login_attempts = {}
blocked_ips = {}
security_logs = []

def log_event(ip_address, action, status):
    """Helper function to record security logs."""
    timestamp = time.strftime('%m-%d-%Y %H:%M:%S')
    security_logs.append({
        'time': timestamp,
        'ip': ip_address,
        'action': action,
        'status': status
    })

@app.before_request
def idps_firewall():
    """IDPS core logic: detects rate-limiting breaches and blocks malicious IPs."""
    ip = request.remote_addr
    current_time = time.time()
    if ip in blocked_ips:
        if current_time < blocked_ips[ip]:
            remaining = int(blocked_ips[ip] - current_time)
            return f"<h1>403 Forbidden: Blocked by IDPS</h1><p>Your IP ({ip}) is blocked due to suspicious activity. Try again in {remaining} seconds.</p>", 403
        else:
            del blocked_ips[ip]
            log_event(ip, "IP Unblocked", "Resolved")

    if ip not in request_history:
        request_history[ip] = []
    
    request_history[ip] = [t for t in request_history[ip] if current_time - t < TIME_WINDOW]
    request_history[ip].append(current_time)

    if len(request_history[ip]) > MAX_REQUESTS:
        blocked_ips[ip] = current_time + BLOCK_TIME
        log_event(ip, "Rate Limit Exceeded (DDoS Attack Attempt)", "IP Blocked")
        return f"<h1>403 Forbidden: Blocked by IDPS</h1><p>Too many requests detected from {ip}. You have been temporary blocked.</p>", 403

@app.route('/')
def home():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip = request.remote_addr
        current_time = time.time()

        if username == 'admin' and password == '@dmin273':
            failed_login_attempts[ip] = []
            session['logged_in'] = True
            log_event(ip, "User Login", "Success")
            return redirect(url_for('dashboard'))
        else:
            if ip not in failed_login_attempts:
                failed_login_attempts[ip] = []
            
            failed_login_attempts[ip] = [t for t in failed_login_attempts[ip] if current_time - t < FAILED_LOGIN_WINDOW]
            failed_login_attempts[ip].append(current_time)

            log_event(ip, f"Failed Login Attempt (User: {username})", "Alert")

            if len(failed_login_attempts[ip]) >= MAX_FAILED_LOGINS:
                blocked_ips[ip] = current_time + BLOCK_TIME
                log_event(ip, "Brute Force Attack Detected", "IP Blocked")
                return f"<h1>403 Forbidden: Blocked by IDPS</h1><p>Multiple failed login attempts detected from {ip}. You have been blocked.</p>", 403

            flash("Invalid credentials, try again.")
            
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    active_blocked_count = len(blocked_ips)
    return render_template('dashboard.html', logs=reversed(security_logs), blocked_count=active_blocked_count)

@app.route('/logout')
def logout():
    log_event(request.remote_addr, "User Logout", "Info")
    session.pop('logged_in', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
