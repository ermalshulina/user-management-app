from flask import Flask, request, redirect, url_for, session, send_from_directory
import sqlite3
import hashlib
from functools import wraps
import os
from werkzeug.utils import secure_filename
from datetime import datetime
import pyotp
import qrcode
from io import BytesIO
import base64

app = Flask(__name__)
app.secret_key = 'your_secret_key_here_2024'

# File upload settings
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def send_email(subject, body, to_email=None):
    print(f"📧 EMAIL: {subject}")
    print(f"Body: {body}")
    return True

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') not in ['admin', 'super_admin']:
            return '<h1>Access Denied</h1><p>You need admin privileges.</p><a href="/">Back</a>'
        return f(*args, **kwargs)
    return decorated_function

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'super_admin':
            return '<h1>Access Denied</h1><p>You need super admin privileges.</p><a href="/">Back</a>'
        return f(*args, **kwargs)
    return decorated_function

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Drop and recreate both tables to ensure proper structure
    cursor.execute('DROP TABLE IF EXISTS users')
    cursor.execute('DROP TABLE IF EXISTS admin_users')
    
    # Users table with profile picture support
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            profile_picture TEXT
        )
    ''')
    
    # Recreate admin users table with proper columns
    cursor.execute('''
        CREATE TABLE admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            two_fa_secret TEXT,
            two_fa_enabled INTEGER DEFAULT 0
        )
    ''')
    
    # Create fresh test accounts
    cursor.execute('INSERT INTO admin_users (username, password, role, two_fa_enabled) VALUES (?, ?, ?, ?)', 
                  ('admin', hash_password('admin123'), 'super_admin', 0))
    cursor.execute('INSERT INTO admin_users (username, password, role, two_fa_enabled) VALUES (?, ?, ?, ?)', 
                  ('viewer', hash_password('viewer123'), 'viewer', 0))
    cursor.execute('INSERT INTO admin_users (username, password, role, two_fa_enabled) VALUES (?, ?, ?, ?)', 
                  ('manager', hash_password('manager123'), 'admin', 0))
    
    # Add some sample users for analytics
    sample_users = [
        ('John Doe', 'john@gmail.com'),
        ('Jane Smith', 'jane@yahoo.com'),
        ('Bob Wilson', 'bob@company.com'),
        ('Alice Johnson', 'alice@gmail.com'),
        ('Mike Brown', 'mike@outlook.com')
    ]
    
    for name, email in sample_users:
        cursor.execute('INSERT INTO users (name, email, profile_picture) VALUES (?, ?, ?)', 
                      (name, email, None))
    
    print("✅ Database recreated with proper structure")
    print("✅ Created test accounts:")
    print("   admin/admin123 (super_admin)")
    print("   manager/manager123 (admin)")
    print("   viewer/viewer123 (viewer)")
    print("✅ Added sample users for analytics")
    
    conn.commit()
    conn.close()

@app.route('/')
@login_required
def home():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM users')
    total_users = cursor.fetchone()[0]
    cursor.execute('SELECT * FROM users ORDER BY id DESC LIMIT 3')
    recent_users = cursor.fetchall()
    conn.close()
    
    username = session.get('username', 'User')
    role = session.get('role', 'user')
    role_display = {
        'super_admin': 'Super Admin', 
        'admin': 'Admin', 
        'viewer': 'Viewer'
    }.get(role, role.title())
    
    # Build recent users table
    recent_html = ""
    if recent_users:
        recent_html = "<table><tr><th>ID</th><th>Name</th><th>Email</th></tr>"
        for user in recent_users:
            recent_html += f"<tr><td>{user[0]}</td><td>{user[1]}</td><td>{user[2]}</td></tr>"
        recent_html += "</table>"
    else:
        recent_html = "<p>No users found.</p>"
    
    # Build action buttons based on role
    action_buttons = '<a href="/users" class="btn">👥 View All Users</a>'
    if role in ['admin', 'super_admin']:
        action_buttons += '<a href="/add_user" class="btn">➕ Add New User</a>'
    if role == 'super_admin':
        action_buttons += '<a href="/admin_panel" class="btn" style="background: #dc3545;">👑 Admin Panel</a>'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; background: #f8f9fa; }}
            .header {{ background: linear-gradient(135deg, #007bff, #0056b3); color: white; padding: 20px; }}
            .header h1 {{ margin: 0; display: inline-block; }}
            .header .user-info {{ float: right; margin-top: 5px; }}
            .header .user-info a {{ color: white; text-decoration: none; margin-left: 15px; padding: 5px 10px; border-radius: 4px; }}
            .header .user-info a:hover {{ background: rgba(255,255,255,0.2); }}
            .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 20px; }}
            .welcome-card {{ background: white; padding: 30px; border-radius: 12px; margin-bottom: 30px; }}
            .role-badge {{ background: #28a745; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; }}
            .stats {{ display: flex; gap: 30px; margin-bottom: 40px; }}
            .stat-card {{ background: white; padding: 30px; border-radius: 12px; flex: 1; text-align: center; }}
            .stat-number {{ font-size: 48px; font-weight: bold; color: #007bff; }}
            .stat-label {{ color: #6c757d; }}
            .recent-users {{ background: white; padding: 30px; border-radius: 12px; margin-bottom: 30px; }}
            .btn {{ background: #007bff; color: white; padding: 15px 30px; text-decoration: none; 
                   border-radius: 8px; margin: 10px; display: inline-block; }}
            .actions {{ text-align: center; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background: #f8f9fa; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Dashboard</h1>
            <div class="user-info">
                Welcome, {username}! <span class="role-badge">{role_display}</span>
                <a href="/security_settings">🔐 Security</a>
                <a href="/logout">Logout</a>
            </div>
            <div style="clear: both;"></div>
        </div>
        
        <div class="container">
            <div class="welcome-card">
                <h2>Welcome to your User Management System!</h2>
                <p>Your access level: <strong>{role_display}</strong></p>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{total_users}</div>
                    <div class="stat-label">Total Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(recent_users)}</div>
                    <div class="stat-label">Recent Users</div>
                </div>
            </div>
            
            <div class="recent-users">
                <h3>Recent Users</h3>
                {recent_html}
            </div>
            
            <div class="actions">
                {action_buttons}
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        totp_code = request.form.get('totp_code', '')
        
        print(f"DEBUG: Login attempt - username: {username}, has_password: {bool(password)}, has_totp: {bool(totp_code)}")
        
        # Handle 2FA verification case
        if totp_code and not password:
            # This is a 2FA verification request
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM admin_users WHERE username = ?', (username,))
            user = cursor.fetchone()
            conn.close()
            
            if user and user[5] and user[4]:  # user exists, 2FA enabled, has secret
                totp = pyotp.TOTP(user[4])
                if totp.verify(totp_code, valid_window=1):
                    session['user_id'] = user[0]
                    session['username'] = user[1]
                    session['role'] = user[3]
                    print("DEBUG: 2FA verified successfully")
                    return redirect(url_for('home'))
                else:
                    print("DEBUG: Invalid 2FA code")
                    return render_login_page('Invalid 2FA code', show_2fa=True, username=username)
            else:
                return render_login_page('Invalid session', show_2fa=False)
        
        # Handle initial login with username/password
        if username and password:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM admin_users WHERE username = ? AND password = ?', 
                          (username, hash_password(password)))
            user = cursor.fetchone()
            conn.close()
            
            if user:
                print(f"DEBUG: User found: {user[1]}")
                print(f"DEBUG: 2FA enabled: {user[5]}")
                print(f"DEBUG: 2FA secret exists: {user[4] is not None}")
                
                # Check if 2FA is enabled
                if user[5] and user[4]:  # two_fa_enabled AND secret exists
                    print("DEBUG: 2FA required, showing 2FA form")
                    return render_login_page('Please enter your 2FA code', show_2fa=True, username=username)
                else:
                    print("DEBUG: 2FA not enabled, proceeding with regular login")
                
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[3]
                return redirect(url_for('home'))
            else:
                return render_login_page('Invalid username or password')
        else:
            return render_login_page('Please enter username and password')
    
    return render_login_page()

def render_login_page(error=None, show_2fa=False, username=''):
    error_html = ""
    if error:
        error_html = f'<div style="color: red; padding: 10px; background: #f8d7da; border-radius: 5px; margin-bottom: 20px;">{error}</div>'
    
    totp_field = ""
    username_field = f'<input type="text" id="username" name="username" value="{username}" required>'
    if show_2fa:
        totp_field = '''
        <div class="form-group">
            <label for="totp_code">2FA Code:</label>
            <input type="text" id="totp_code" name="totp_code" placeholder="6-digit code" maxlength="6" required>
        </div>'''
        username_field = f'<input type="hidden" name="username" value="{username}"><p><strong>Username:</strong> {username}</p>'
    
    # Build bottom links without backslashes in f-string
    if show_2fa:
        bottom_links = '<div class="register-link"><a href="/login">← Back to login</a></div>'
        two_fa_info = '<div class="two-fa-info">🔐 <strong>2FA Required:</strong> Enter your 6-digit authenticator code</div>'
        accounts_info = ''
        password_field = '<input type="hidden" name="password" value="">'
        button_text = 'Verify 2FA'
    else:
        bottom_links = '<div class="register-link">Don\'t have an account? <a href="/register">Create one here</a></div>'
        two_fa_info = ''
        accounts_info = '<div class="accounts"><strong>Test Accounts:</strong><br>• super_admin: admin/admin123<br>• admin: manager/manager123<br>• viewer: viewer/viewer123</div>'
        password_field = '<div class="form-group"><label for="password">Password:</label><input type="password" id="password" name="password" required></div>'
        button_text = 'Login'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }}
            .login-container {{ max-width: 400px; margin: 100px auto; background: white; padding: 40px; border-radius: 15px; }}
            .form-group {{ margin-bottom: 20px; }}
            .form-group label {{ display: block; margin-bottom: 8px; font-weight: bold; }}
            .form-group input {{ width: 100%; padding: 12px; border: 2px solid #e1e1e1; border-radius: 8px; box-sizing: border-box; }}
            .btn {{ width: 100%; background: #007bff; color: white; padding: 15px; border: none; border-radius: 8px; cursor: pointer; }}
            .accounts {{ background: #e9ecef; padding: 15px; border-radius: 8px; margin: 20px 0; font-size: 14px; }}
            .register-link {{ text-align: center; margin-top: 25px; }}
            .register-link a {{ color: #007bff; text-decoration: none; }}
            .two-fa-info {{ background: #fff3cd; padding: 15px; border-radius: 8px; margin: 20px 0; }}
        </style>
    </head>
    <body>
        <div class="login-container">
            <h2 style="text-align: center;">🔐 Secure Login</h2>
            {error_html}
            
            {two_fa_info}
            {accounts_info}
            
            <form method="POST">
                <div class="form-group">
                    <label for="username">Username:</label>
                    {username_field}
                </div>
                {password_field}
                {totp_field}
                <button type="submit" class="btn">{button_text}</button>
            </form>
            
            {bottom_links}
        </div>
    </body>
    </html>
    '''

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            return render_register_page('Passwords do not match')
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM admin_users WHERE username = ?', (username,))
        if cursor.fetchone():
            conn.close()
            return render_register_page('Username already exists')
        
        cursor.execute('INSERT INTO admin_users (username, password, role) VALUES (?, ?, ?)', 
                      (username, hash_password(password), 'admin'))
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        session['user_id'] = user_id
        session['username'] = username
        session['role'] = 'admin'
        return redirect(url_for('home'))
    
    return render_register_page()

def render_register_page(error=None):
    error_html = ""
    if error:
        error_html = f'<div style="color: red; padding: 10px; background: #f8d7da; border-radius: 5px; margin-bottom: 20px;">{error}</div>'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }}
            .register-container {{ max-width: 400px; margin: 80px auto; background: white; padding: 40px; border-radius: 15px; }}
            .form-group {{ margin-bottom: 20px; }}
            .form-group label {{ display: block; margin-bottom: 8px; font-weight: bold; }}
            .form-group input {{ width: 100%; padding: 12px; border: 2px solid #e1e1e1; border-radius: 8px; box-sizing: border-box; }}
            .btn {{ width: 100%; background: #28a745; color: white; padding: 15px; border: none; border-radius: 8px; cursor: pointer; }}
            .login-link {{ text-align: center; margin-top: 25px; }}
            .login-link a {{ color: #007bff; text-decoration: none; }}
        </style>
    </head>
    <body>
        <div class="register-container">
            <h2 style="text-align: center;">Create Account</h2>
            {error_html}
            <p style="text-align: center; color: #666;">New accounts get Admin role</p>
            <form method="POST">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <div class="form-group">
                    <label for="confirm_password">Confirm Password:</label>
                    <input type="password" id="confirm_password" name="confirm_password" required>
                </div>
                <button type="submit" class="btn">Create Account</button>
            </form>
            <div class="login-link">
                Already have an account? <a href="/login">Login here</a>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/users')
@login_required
def users():
    search_query = request.args.get('search', '')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    if search_query:
        cursor.execute('SELECT * FROM users WHERE name LIKE ? OR email LIKE ?', 
                      (f'%{search_query}%', f'%{search_query}%'))
    else:
        cursor.execute('SELECT * FROM users')
    
    users_list = cursor.fetchall()
    conn.close()
    
    username = session.get('username', 'User')
    role = session.get('role', 'user')
    can_edit = role in ['admin', 'super_admin']
    
    # Build users table
    users_html = ""
    if users_list:
        users_html = "<table><tr><th>Picture</th><th>ID</th><th>Name</th><th>Email</th>"
        if can_edit:
            users_html += "<th>Actions</th>"
        users_html += "</tr>"
        
        for user in users_list:
            pic_html = '👤'
            # Check if user has profile_picture column (index 3)
            if len(user) > 3 and user[3]:
                pic_html = f'<img src="/uploads/{user[3]}" style="width:50px;height:50px;border-radius:50%;object-fit:cover;">'
            
            users_html += f"<tr><td>{pic_html}</td><td>{user[0]}</td><td>{user[1]}</td><td>{user[2]}</td>"
            
            if can_edit:
                users_html += f'<td><a href="/edit_user/{user[0]}" class="btn-edit">Edit</a> <a href="/delete_user/{user[0]}" class="btn-delete" onclick="return confirm(\'Delete?\')">Delete</a></td>'
            
            users_html += "</tr>"
        users_html += "</table>"
    else:
        users_html = "<p>No users found.</p>"
    
    add_button = ""
    if can_edit:
        add_button = '<a href="/add_user" class="btn">Add New User</a>'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Users</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; background: #f8f9fa; }}
            .header {{ background: #007bff; color: white; padding: 20px; }}
            .header h1 {{ margin: 0; display: inline-block; }}
            .header .user-info {{ float: right; margin-top: 5px; }}
            .header .user-info a {{ color: white; text-decoration: none; margin-left: 20px; }}
            .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
            .search-box {{ background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
            .search-box input {{ padding: 10px; border: 1px solid #ddd; border-radius: 4px; width: 300px; }}
            .search-box button {{ background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; margin-left: 10px; }}
            .btn {{ background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; margin: 5px; }}
            .btn-edit {{ background: #28a745; color: white; padding: 5px 10px; text-decoration: none; border-radius: 4px; margin: 2px; }}
            .btn-delete {{ background: #dc3545; color: white; padding: 5px 10px; text-decoration: none; border-radius: 4px; margin: 2px; }}
            table {{ width: 100%; border-collapse: collapse; background: white; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background: #f8f9fa; }}
            .actions {{ margin: 20px 0; }}
            .role-info {{ background: #e9ecef; padding: 10px; border-radius: 4px; margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Users Management</h1>
            <div class="user-info">
                {username} ({role})
                <a href="/logout">Logout</a>
            </div>
            <div style="clear: both;"></div>
        </div>
        
        <div class="container">
            <div class="role-info">
                Your access level: <strong>{role.title()}</strong>
                {" - You can view, edit and delete users" if can_edit else " - You can only view users"}
            </div>
            
            <div class="search-box">
                <form method="GET">
                    <input type="text" name="search" placeholder="Search users..." value="{search_query}">
                    <button type="submit">Search</button>
                    <a href="/users" class="btn">Clear</a>
                </form>
            </div>
            
            <div class="actions">
                <a href="/" class="btn">Back to Dashboard</a>
                {add_button}
            </div>
            
            <p><strong>{len(users_list)} user(s) found</strong></p>
            
            {users_html}
        </div>
    </body>
    </html>
    '''

@app.route('/add_user', methods=['GET', 'POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        
        profile_picture = None
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                import time
                filename = f"{int(time.time())}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                profile_picture = filename
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (name, email, profile_picture) VALUES (?, ?, ?)', 
                      (name, email, profile_picture))
        conn.commit()
        conn.close()
        
        send_email("New User Added", f"User {name} was added by {session.get('username')}")
        return redirect(url_for('users'))
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Add User</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f8f9fa; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; }
            .form-group { margin-bottom: 20px; }
            .form-group label { display: block; margin-bottom: 8px; font-weight: bold; }
            .form-group input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
            .btn { background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
            .btn-secondary { background: #6c757d; margin-left: 10px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Add New User (Admin Access)</h1>
            <form method="POST" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="name">Name:</label>
                    <input type="text" id="name" name="name" required>
                </div>
                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" required>
                </div>
                <div class="form-group">
                    <label for="profile_picture">Profile Picture:</label>
                    <input type="file" id="profile_picture" name="profile_picture" accept=".png,.jpg,.jpeg,.gif">
                </div>
                <button type="submit" class="btn">Add User</button>
                <a href="/users" class="btn btn-secondary">Cancel</a>
            </form>
        </div>
    </body>
    </html>
    '''

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        
        cursor.execute('UPDATE users SET name = ?, email = ? WHERE id = ?', (name, email, user_id))
        conn.commit()
        conn.close()
        
        send_email("User Updated", f"User {name} was updated by {session.get('username')}")
        return redirect(url_for('users'))
    
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return redirect(url_for('users'))
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Edit User</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f8f9fa; }}
            .container {{ max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; }}
            .form-group {{ margin-bottom: 20px; }}
            .form-group label {{ display: block; margin-bottom: 8px; font-weight: bold; }}
            .form-group input {{ width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
            .btn {{ background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }}
            .btn-secondary {{ background: #6c757d; margin-left: 10px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Edit User (Admin Access)</h1>
            <form method="POST">
                <div class="form-group">
                    <label for="name">Name:</label>
                    <input type="text" id="name" name="name" value="{user[1]}" required>
                </div>
                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" value="{user[2]}" required>
                </div>
                <button type="submit" class="btn">Update User</button>
                <a href="/users" class="btn btn-secondary">Cancel</a>
            </form>
        </div>
    </body>
    </html>
    '''

@app.route('/delete_user/<int:user_id>')
@admin_required
def delete_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    if user:
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        send_email("User Deleted", f"User {user[1]} was deleted by {session.get('username')}")
    
    conn.close()
    return redirect(url_for('users'))

@app.route('/security_settings')
@login_required
def security_settings():
    role = session.get('role', 'user')
    user_id = session.get('user_id')
    
    print(f"DEBUG: Checking 2FA for user_id: {user_id}")
    
    # Check if 2FA is enabled
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT two_fa_enabled, two_fa_secret FROM admin_users WHERE id = ?', (user_id,))
    result = cursor.fetchone()
    
    if result:
        two_fa_enabled = result[0]
        has_secret = result[1] is not None
        print(f"DEBUG: 2FA enabled: {two_fa_enabled}, Has secret: {has_secret}")
    else:
        print("DEBUG: User not found in database!")
        two_fa_enabled = 0
    
    conn.close()
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Settings</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f8f9fa; }}
            .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; }}
            .security-option {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
            .btn {{ background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }}
            .btn-danger {{ background: #dc3545; }}
            .btn-success {{ background: #28a745; }}
            .status {{ padding: 10px; border-radius: 4px; margin: 10px 0; }}
            .enabled {{ background: #d4edda; color: #155724; }}
            .disabled {{ background: #f8d7da; color: #721c24; }}
            .role-badge {{ background: #007bff; color: white; padding: 4px 12px; border-radius: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Security Settings</h1>
            
            <div class="security-option">
                <h3>Account Information</h3>
                <p>Username: <strong>{session.get('username')}</strong></p>
                <p>Role: <span class="role-badge">{role.title()}</span></p>
                <p>Access Level: {{'Full system access' if role == 'super_admin' else 'User management' if role == 'admin' else 'View only'}}</p>
            </div>
            
            <div class="security-option">
                <h3>Two-Factor Authentication (2FA)</h3>
                {'<div class="status enabled">✅ <strong>Enabled</strong> - Your account has an extra layer of security</div>' if two_fa_enabled else '<div class="status disabled">❌ <strong>Disabled</strong> - Your account is protected by password only</div>'}
                
                <p>Add an extra layer of security with 2FA using Google Authenticator or similar apps.</p>
                
                {f'<a href="/disable_2fa" class="btn btn-danger">🔓 Disable 2FA</a>' if two_fa_enabled else '<a href="/setup_2fa" class="btn btn-success">🔐 Enable 2FA</a>'}
            </div>
            
            <div class="security-option">
                <h3>Password Security</h3>
                <p>Keep your account secure with a strong password.</p>
                <a href="#" class="btn">🔑 Change Password (Coming Soon)</a>
            </div>
            
            <div class="security-option">
                <h3>Session Management</h3>
                <p>Manage your login sessions and logout from all devices.</p>
                <a href="/logout" class="btn btn-danger">🚪 Logout</a>
            </div>
            
            <p><a href="/">← Back to Dashboard</a></p>
        </div>
    </body>
    </html>
    '''

@app.route('/setup_2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    user_id = session.get('user_id')
    username = session.get('username')
    
    print(f"DEBUG: Setting up 2FA for user_id: {user_id}, username: {username}")
    
    if request.method == 'POST':
        totp_code = request.form['totp_code']
        secret = request.form['secret']
        
        print(f"DEBUG: Received TOTP code: {totp_code}")
        print(f"DEBUG: Secret: {secret}")
        
        # Verify the code
        totp = pyotp.TOTP(secret)
        is_valid = totp.verify(totp_code, valid_window=1)
        print(f"DEBUG: Code verification result: {is_valid}")
        
        if is_valid:
            # Save the secret and enable 2FA
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            
            # First check current state
            cursor.execute('SELECT two_fa_enabled, two_fa_secret FROM admin_users WHERE id = ?', (user_id,))
            before = cursor.fetchone()
            print(f"DEBUG: Before update - 2FA enabled: {before[0] if before else 'None'}, Secret: {before[1] is not None if before else 'None'}")
            
            cursor.execute('UPDATE admin_users SET two_fa_secret = ?, two_fa_enabled = 1 WHERE id = ?', 
                          (secret, user_id))
            rows_affected = cursor.rowcount
            conn.commit()
            
            print(f"DEBUG: Update query affected {rows_affected} rows")
            
            # Check after update
            cursor.execute('SELECT two_fa_enabled, two_fa_secret FROM admin_users WHERE id = ?', (user_id,))
            after = cursor.fetchone()
            
            if after:
                print(f"DEBUG: After update - 2FA enabled: {after[0]}, Secret exists: {after[1] is not None}")
            else:
                print("DEBUG: ERROR - User not found after update!")
            
            conn.close()
            
            return '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>2FA Enabled</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; background: #f8f9fa; text-align: center; }
                    .success { background: #d4edda; color: #155724; padding: 30px; border-radius: 8px; max-width: 500px; margin: 50px auto; }
                    .btn { background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 4px; text-decoration: none; display: inline-block; margin-top: 20px; }
                </style>
            </head>
            <body>
                <div class="success">
                    <h2>🎉 2FA Successfully Enabled!</h2>
                    <p>Your account is now protected with two-factor authentication.</p>
                    <p>You'll need your authenticator app for future logins.</p>
                    <a href="/security_settings" class="btn">Back to Security Settings</a>
                </div>
            </body>
            </html>
            '''
        else:
            print("DEBUG: Code verification failed")
            return render_2fa_setup(secret, 'Invalid code. Please try again.')
    
    # Generate new secret
    secret = pyotp.random_base32()
    print(f"DEBUG: Generated new secret: {secret}")
    return render_2fa_setup(secret)

def render_2fa_setup(secret, error=None):
    username = session.get('username')
    
    # Generate QR code
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="User Management System"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    error_html = f'<div style="color: red; padding: 10px; background: #f8d7da; border-radius: 5px; margin-bottom: 20px;">{error}</div>' if error else ''
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Setup 2FA</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f8f9fa; }}
            .container {{ max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; }}
            .step {{ background: #e9ecef; padding: 15px; border-radius: 8px; margin: 15px 0; }}
            .qr-code {{ text-align: center; margin: 20px 0; }}
            .secret {{ background: #f8f9fa; padding: 15px; border-radius: 8px; font-family: monospace; word-break: break-all; }}
            .form-group {{ margin-bottom: 20px; }}
            .form-group label {{ display: block; margin-bottom: 8px; font-weight: bold; }}
            .form-group input {{ width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
            .btn {{ background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }}
            .btn-secondary {{ background: #6c757d; margin-left: 10px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Setup Two-Factor Authentication</h1>
            {error_html}
            
            <div class="step">
                <h3>Step 1: Install Authenticator App</h3>
                <p>Download one of these apps on your phone:</p>
                <ul>
                    <li><strong>Google Authenticator</strong> (iOS/Android)</li>
                    <li><strong>Authy</strong> (iOS/Android)</li>
                    <li><strong>Microsoft Authenticator</strong> (iOS/Android)</li>
                </ul>
            </div>
            
            <div class="step">
                <h3>Step 2: Scan QR Code</h3>
                <p>Open your authenticator app and scan this QR code:</p>
                <div class="qr-code">
                    <img src="data:image/png;base64,{img_str}" alt="QR Code">
                </div>
                <p><strong>Can't scan?</strong> Enter this secret manually:</p>
                <div class="secret">{secret}</div>
            </div>
            
            <div class="step">
                <h3>Step 3: Verify Setup</h3>
                <p>Enter the 6-digit code from your authenticator app:</p>
                
                <form method="POST">
                    <input type="hidden" name="secret" value="{secret}">
                    <div class="form-group">
                        <label for="totp_code">6-Digit Code:</label>
                        <input type="text" id="totp_code" name="totp_code" placeholder="123456" maxlength="6" required>
                    </div>
                    <button type="submit" class="btn">✅ Enable 2FA</button>
                    <a href="/security_settings" class="btn btn-secondary">Cancel</a>
                </form>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/disable_2fa', methods=['POST', 'GET'])
@login_required
def disable_2fa():
    if request.method == 'POST':
        user_id = session.get('user_id')
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE admin_users SET two_fa_secret = NULL, two_fa_enabled = 0 WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        
        return redirect(url_for('security_settings'))
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Disable 2FA</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f8f9fa; }
            .container { max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; text-align: center; }
            .warning { background: #fff3cd; color: #856404; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .btn { background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; margin: 10px; }
            .btn-danger { background: #dc3545; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🔓 Disable Two-Factor Authentication</h2>
            
            <div class="warning">
                <h4>⚠️ Security Warning</h4>
                <p>Disabling 2FA will make your account less secure. You'll only be protected by your password.</p>
            </div>
            
            <p>Are you sure you want to disable 2FA?</p>
            
            <form method="POST">
                <button type="submit" class="btn btn-danger">Yes, Disable 2FA</button>
                <a href="/security_settings" class="btn">Cancel</a>
            </form>
        </div>
    </body>
    </html>
    '''

@app.route('/admin_panel')
@super_admin_required
def admin_panel():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM admin_users')
    admin_users = cursor.fetchall()
    conn.close()
    
    admins_html = "<table><tr><th>ID</th><th>Username</th><th>Role</th><th>2FA</th><th>Actions</th></tr>"
    for admin in admin_users:
        two_fa_status = "✅ Enabled" if admin[5] else "❌ Disabled"
        role_color = {"super_admin": "#dc3545", "admin": "#007bff", "viewer": "#28a745"}.get(admin[3], "#6c757d")
        
        delete_btn = ""
        if admin[0] != session.get('user_id'):
            delete_btn = f'<a href="#" class="btn-delete" onclick="return confirm(\'Delete admin?\')">Delete</a>'
        
        admins_html += f'''
            <tr>
                <td>{admin[0]}</td>
                <td>{admin[1]}</td>
                <td><span style="background:{role_color}; color:white; padding:2px 8px; border-radius:10px; font-size:12px;">{admin[3]}</span></td>
                <td>{two_fa_status}</td>
                <td>
                    <a href="#" class="btn-edit">Change Role</a>
                    {delete_btn}
                </td>
            </tr>'''
    admins_html += "</table>"
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f8f9fa; }}
            .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background: #f8f9fa; }}
            .btn {{ background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; margin: 5px; }}
            .btn-edit {{ background: #28a745; color: white; padding: 5px 10px; text-decoration: none; border-radius: 4px; margin: 2px; }}
            .btn-delete {{ background: #dc3545; color: white; padding: 5px 10px; text-decoration: none; border-radius: 4px; margin: 2px; }}
            .admin-section {{ background: #fff3cd; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ffc107; }}
            .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
            .stat-box {{ background: #e9ecef; padding: 15px; border-radius: 8px; flex: 1; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>👑 Super Admin Panel</h1>
            
            <div class="admin-section">
                <h3>⚠️ Super Admin Access</h3>
                <p>You have full system access. Use these powers responsibly!</p>
            </div>
            
            <div class="stats">
                <div class="stat-box">
                    <h3>{len(admin_users)}</h3>
                    <p>Total Admins</p>
                </div>
                <div class="stat-box">
                    <h3>{len([a for a in admin_users if a[5]])}</h3>
                    <p>2FA Enabled</p>
                </div>
                <div class="stat-box">
                    <h3>{len([a for a in admin_users if a[3] == 'super_admin'])}</h3>
                    <p>Super Admins</p>
                </div>
            </div>
            
            <h3>System Administrators</h3>
            {admins_html}
            
            <div style="margin: 30px 0;">
                <a href="#" class="btn">➕ Create New Admin (Coming Soon)</a>
                <a href="#" class="btn" style="background: #6c757d;">📋 System Logs (Coming Soon)</a>
            </div>
            
            <p><a href="/">← Back to Dashboard</a></p>
        </div>
    </body>
    </html>
    '''

@app.route('/analytics')
@login_required
def analytics():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Get basic stats
    cursor.execute('SELECT COUNT(*) FROM users')
    total_users = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM admin_users')
    total_admins = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM admin_users WHERE two_fa_enabled = 1')
    admins_with_2fa = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM users WHERE profile_picture IS NOT NULL')
    users_with_pics = cursor.fetchone()[0]
    
    # Get users by email domain
    cursor.execute('''
        SELECT substr(email, instr(email, "@") + 1) as domain, COUNT(*) as count 
        FROM users 
        GROUP BY domain 
        ORDER BY count DESC 
        LIMIT 10
    ''')
    domain_data = cursor.fetchall()
    
    # Get admin roles distribution
    cursor.execute('SELECT role, COUNT(*) FROM admin_users GROUP BY role')
    role_data = cursor.fetchall()
    
    # Get recent activity (last 30 users)
    cursor.execute('SELECT id FROM users ORDER BY id DESC LIMIT 30')
    recent_activity = len(cursor.fetchall())
    
    conn.close()
    
    # Prepare data for charts
    domain_labels = [d[0] for d in domain_data] if domain_data else ['No data']
    domain_values = [d[1] for d in domain_data] if domain_data else [0]
    
    role_labels = [r[0].replace('_', ' ').title() for r in role_data]
    role_values = [r[1] for r in role_data]
    
    username = session.get('username', 'User')
    role = session.get('role', 'user')
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Analytics Dashboard</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; background: #f8f9fa; }}
            .header {{ background: linear-gradient(135deg, #007bff, #0056b3); color: white; padding: 20px; }}
            .header h1 {{ margin: 0; display: inline-block; }}
            .header .user-info {{ float: right; margin-top: 5px; }}
            .header .user-info a {{ color: white; text-decoration: none; margin-left: 15px; padding: 5px 10px; border-radius: 4px; }}
            .header .user-info a:hover {{ background: rgba(255,255,255,0.2); }}
            .container {{ max-width: 1400px; margin: 0 auto; padding: 40px 20px; }}
            
            .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 40px; }}
            .stat-card {{ background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); text-align: center; transition: transform 0.3s; }}
            .stat-card:hover {{ transform: translateY(-5px); }}
            .stat-number {{ font-size: 42px; font-weight: bold; margin-bottom: 10px; }}
            .stat-label {{ color: #6c757d; font-size: 16px; }}
            .stat-users {{ color: #007bff; }}
            .stat-admins {{ color: #28a745; }}
            .stat-security {{ color: #dc3545; }}
            .stat-activity {{ color: #17a2b8; }}
            
            .charts-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 30px; margin-bottom: 40px; }}
            .chart-card {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
            .chart-card h3 {{ margin-top: 0; color: #333; text-align: center; }}
            .chart-container {{ position: relative; height: 300px; }}
            
            .insights {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); margin-bottom: 30px; }}
            .insight-item {{ background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 10px 0; border-left: 4px solid #007bff; }}
            
            .btn {{ background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; display: inline-block; margin: 10px; }}
            .btn:hover {{ background: #0056b3; }}
            .actions {{ text-align: center; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>📊 Analytics Dashboard</h1>
            <div class="user-info">
                {username} ({role})
                <a href="/security_settings">🔐 Security</a>
                <a href="/logout">Logout</a>
            </div>
            <div style="clear: both;"></div>
        </div>
        
        <div class="container">
            <!-- Key Metrics -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number stat-users">{total_users}</div>
                    <div class="stat-label">Total Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number stat-admins">{total_admins}</div>
                    <div class="stat-label">System Administrators</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number stat-security">{admins_with_2fa}</div>
                    <div class="stat-label">Admins with 2FA</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number stat-activity">{users_with_pics}</div>
                    <div class="stat-label">Users with Photos</div>
                </div>
            </div>
            
            <!-- Charts -->
            <div class="charts-grid">
                <div class="chart-card">
                    <h3>Users by Email Domain</h3>
                    <div class="chart-container">
                        <canvas id="domainChart"></canvas>
                    </div>
                </div>
                
                <div class="chart-card">
                    <h3>Admin Roles Distribution</h3>
                    <div class="chart-container">
                        <canvas id="roleChart"></canvas>
                    </div>
                </div>
                
                <div class="chart-card">
                    <h3>Profile Pictures Status</h3>
                    <div class="chart-container">
                        <canvas id="pictureChart"></canvas>
                    </div>
                </div>
                
                <div class="chart-card">
                    <h3>Security Overview</h3>
                    <div class="chart-container">
                        <canvas id="securityChart"></canvas>
                    </div>
                </div>
            </div>
            
            <!-- Insights -->
            <div class="insights">
                <h3>📈 Key Insights</h3>
                <div class="insight-item">
                    <strong>Security Score:</strong> {round((admins_with_2fa / max(total_admins, 1)) * 100)}% of administrators have 2FA enabled
                </div>
                <div class="insight-item">
                    <strong>User Engagement:</strong> {round((users_with_pics / max(total_users, 1)) * 100)}% of users have uploaded profile pictures
                </div>
                <div class="insight-item">
                    <strong>Email Diversity:</strong> Users registered with {len(domain_data)} different email domains
                </div>
                <div class="insight-item">
                    <strong>System Health:</strong> {total_users + total_admins} total accounts in the system
                </div>
            </div>
            
            <div class="actions">
                <a href="/" class="btn">🏠 Back to Dashboard</a>
                <a href="/users" class="btn">👥 View Users</a>
                {f'<a href="/admin_panel" class="btn" style="background: #dc3545;">👑 Admin Panel</a>' if role == 'super_admin' else ''}
            </div>
        </div>
        
        <script>
            // Domain Chart
            const domainCtx = document.getElementById('domainChart').getContext('2d');
            new Chart(domainCtx, {{
                type: 'doughnut',
                data: {{
                    labels: {domain_labels},
                    datasets: [{{
                        data: {domain_values},
                        backgroundColor: [
                            '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0',
                            '#9966FF', '#FF9F40', '#FF6384', '#36A2EB'
                        ],
                        borderWidth: 2
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{ position: 'bottom' }}
                    }}
                }}
            }});
            
            // Role Chart
            const roleCtx = document.getElementById('roleChart').getContext('2d');
            new Chart(roleCtx, {{
                type: 'pie',
                data: {{
                    labels: {role_labels},
                    datasets: [{{
                        data: {role_values},
                        backgroundColor: ['#DC3545', '#007BFF', '#28A745'],
                        borderWidth: 2
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{ position: 'bottom' }}
                    }}
                }}
            }});
            
            // Picture Status Chart
            const pictureCtx = document.getElementById('pictureChart').getContext('2d');
            new Chart(pictureCtx, {{
                type: 'bar',
                data: {{
                    labels: ['With Pictures', 'Without Pictures'],
                    datasets: [{{
                        label: 'Users',
                        data: [{users_with_pics}, {total_users - users_with_pics}],
                        backgroundColor: ['#28A745', '#DC3545'],
                        borderWidth: 2
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{ display: false }}
                    }},
                    scales: {{
                        y: {{ beginAtZero: true }}
                    }}
                }}
            }});
            
            // Security Chart
            const securityCtx = document.getElementById('securityChart').getContext('2d');
            new Chart(securityCtx, {{
                type: 'radar',
                data: {{
                    labels: ['2FA Enabled', 'Admin Security', 'User Profiles', 'System Access'],
                    datasets: [{{
                        label: 'Security Score',
                        data: [
                            {round((admins_with_2fa / max(total_admins, 1)) * 100)},
                            {round((total_admins / max(total_admins + total_users, 1)) * 100)},
                            {round((users_with_pics / max(total_users, 1)) * 100)},
                            85
                        ],
                        backgroundColor: 'rgba(0, 123, 255, 0.2)',
                        borderColor: '#007BFF',
                        borderWidth: 2
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        r: {{
                            beginAtZero: true,
                            max: 100
                        }}
                    }}
                }}
            }});
        </script>
    </body>
    </html>
    '''

if __name__ == '__main__':
    print("Starting Secure Flask App with Analytics...")
    print("🔐 Security Features: Role-based access + 2FA")
    print("📊 Analytics Dashboard included")
    print("🎨 Professional UI with charts")
    
    if os.environ.get('FLASK_ENV') == 'production':
        print("🌐 Running in PRODUCTION mode")
    else:
        print("💻 Running in DEVELOPMENT mode")
        print("Test accounts:")
        print("  Super Admin: admin/admin123")
        print("  Admin: manager/manager123") 
        print("  Viewer: viewer/viewer123")
    
    init_db()
    
    # Get port from environment for deployment
    port = int(os.environ.get('PORT', 8000))
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
