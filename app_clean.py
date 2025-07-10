from flask import Flask, request, redirect, url_for, session, send_from_directory
import sqlite3
import hashlib
from functools import wraps
import os
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# File upload settings
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Create uploads directory
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Email settings
EMAIL_SETTINGS = {
    'enabled': False,
    'email': 'your-email@gmail.com',
    'admin_email': 'admin@company.com'
}

def send_email(subject, body, to_email=None):
    try:
        if not EMAIL_SETTINGS['enabled']:
            print(f"📧 EMAIL: {subject}")
            print(f"Body: {body}")
            return True
        # Real email would go here
        return True
    except:
        return False

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            profile_picture TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    cursor.execute('SELECT COUNT(*) FROM admin_users')
    if cursor.fetchone()[0] == 0:
        cursor.execute('INSERT INTO admin_users (username, password) VALUES (?, ?)', 
                      ('admin', hash_password('admin123')))
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
    
    recent_html = ""
    if recent_users:
        recent_html = "<table><tr><th>ID</th><th>Name</th><th>Email</th></tr>"
        for user in recent_users:
            recent_html += f"<tr><td>{user[0]}</td><td>{user[1]}</td><td>{user[2]}</td></tr>"
        recent_html += "</table>"
    else:
        recent_html = "<p>No users found.</p>"
    
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
            .header .user-info a {{ color: white; text-decoration: none; margin-left: 20px; }}
            .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 20px; }}
            .welcome-card {{ background: white; padding: 30px; border-radius: 12px; margin-bottom: 30px; }}
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
                Welcome, {username}!
                <a href="/logout">Logout</a>
            </div>
            <div style="clear: both;"></div>
        </div>
        
        <div class="container">
            <div class="welcome-card">
                <h2>Welcome to your User Management System!</h2>
                <p>Monitor your users and manage your system efficiently.</p>
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
                <a href="/users" class="btn">👥 View All Users</a>
                <a href="/add_user" class="btn">➕ Add New User</a>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM admin_users WHERE username = ? AND password = ?', 
                      (username, hash_password(password)))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('home'))
        else:
            return render_login_page('Invalid username or password')
    
    return render_login_page()

def render_login_page(error=None):
    error_html = f'<div style="color: red; padding: 10px; background: #f8d7da; border-radius: 5px; margin-bottom: 20px;">{error}</div>' if error else ''
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }}
            .login-container {{ max-width: 400px; margin: 100px auto; background: white; 
                               padding: 40px; border-radius: 15px; }}
            .form-group {{ margin-bottom: 20px; }}
            .form-group label {{ display: block; margin-bottom: 8px; font-weight: bold; }}
            .form-group input {{ width: 100%; padding: 12px; border: 2px solid #e1e1e1; 
                               border-radius: 8px; box-sizing: border-box; }}
            .btn {{ width: 100%; background: #007bff; color: white; padding: 15px; 
                   border: none; border-radius: 8px; cursor: pointer; }}
            .register-link {{ text-align: center; margin-top: 25px; }}
            .register-link a {{ color: #007bff; text-decoration: none; }}
        </style>
    </head>
    <body>
        <div class="login-container">
            <h2 style="text-align: center;">Login</h2>
            {error_html}
            <form method="POST">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="btn">Login</button>
            </form>
            <div class="register-link">
                Don't have an account? <a href="/register">Create one here</a>
            </div>
            <p style="text-align: center; color: #666; font-size: 14px;">
                Demo: admin / admin123
            </p>
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
        
        cursor.execute('INSERT INTO admin_users (username, password) VALUES (?, ?)', 
                      (username, hash_password(password)))
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        session['user_id'] = user_id
        session['username'] = username
        return redirect(url_for('home'))
    
    return render_register_page()

def render_register_page(error=None):
    error_html = f'<div style="color: red; padding: 10px; background: #f8d7da; border-radius: 5px; margin-bottom: 20px;">{error}</div>' if error else ''
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }}
            .register-container {{ max-width: 400px; margin: 80px auto; background: white; 
                                   padding: 40px; border-radius: 15px; }}
            .form-group {{ margin-bottom: 20px; }}
            .form-group label {{ display: block; margin-bottom: 8px; font-weight: bold; }}
            .form-group input {{ width: 100%; padding: 12px; border: 2px solid #e1e1e1; 
                               border-radius: 8px; box-sizing: border-box; }}
            .btn {{ width: 100%; background: #28a745; color: white; padding: 15px; 
                   border: none; border-radius: 8px; cursor: pointer; }}
            .login-link {{ text-align: center; margin-top: 25px; }}
            .login-link a {{ color: #007bff; text-decoration: none; }}
        </style>
    </head>
    <body>
        <div class="register-container">
            <h2 style="text-align: center;">Create Account</h2>
            {error_html}
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
    
    # Build users table
    users_html = ""
    if users_list:
        users_html = "<table><tr><th>Picture</th><th>ID</th><th>Name</th><th>Email</th><th>Actions</th></tr>"
        for user in users_list:
            pic_html = f'<img src="/uploads/{user[3]}" style="width:50px;height:50px;border-radius:50%;object-fit:cover;">' if user[3] else '👤'
            users_html += f'''
                <tr>
                    <td>{pic_html}</td>
                    <td>{user[0]}</td>
                    <td>{user[1]}</td>
                    <td>{user[2]}</td>
                    <td>
                        <a href="/edit_user/{user[0]}" class="btn-edit">Edit</a>
                        <a href="/delete_user/{user[0]}" class="btn-delete" 
                           onclick="return confirm('Delete this user?')">Delete</a>
                    </td>
                </tr>'''
        users_html += "</table>"
    else:
        if search_query:
            users_html = f'<p>No users found for "{search_query}"</p>'
        else:
            users_html = '<p>No users found.</p>'
    
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
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Users Management</h1>
            <div class="user-info">
                Welcome, {username}!
                <a href="/logout">Logout</a>
            </div>
            <div style="clear: both;"></div>
        </div>
        
        <div class="container">
            <div class="search-box">
                <form method="GET">
                    <input type="text" name="search" placeholder="Search users..." value="{search_query}">
                    <button type="submit">Search</button>
                    <a href="/users" class="btn">Clear</a>
                </form>
            </div>
            
            <div class="actions">
                <a href="/" class="btn">Back to Dashboard</a>
                <a href="/add_user" class="btn">Add New User</a>
            </div>
            
            <p><strong>{len(users_list)} user(s) found</strong></p>
            
            {users_html}
        </div>
    </body>
    </html>
    '''

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
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
        
        send_email("New User Added", f"User {name} was added")
        
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
            .btn { background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; }
            .btn-secondary { background: #6c757d; margin-left: 10px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Add New User</h1>
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
@login_required
def edit_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        
        cursor.execute('SELECT profile_picture FROM users WHERE id = ?', (user_id,))
        current_picture = cursor.fetchone()[0]
        
        profile_picture = current_picture
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename != '' and allowed_file(file.filename):
                if current_picture:
                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], current_picture)
                    if os.path.exists(old_path):
                        os.remove(old_path)
                
                filename = secure_filename(file.filename)
                import time
                filename = f"{int(time.time())}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                profile_picture = filename
        
        cursor.execute('UPDATE users SET name = ?, email = ?, profile_picture = ? WHERE id = ?', 
                      (name, email, profile_picture, user_id))
        conn.commit()
        conn.close()
        
        send_email("User Updated", f"User {name} was updated")
        
        return redirect(url_for('users'))
    
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return redirect(url_for('users'))
    
    current_pic = f'<img src="/uploads/{user[3]}" style="width:100px;height:100px;border-radius:50%;">' if user[3] else '👤 No picture'
    
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
            .current-pic {{ text-align: center; margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Edit User</h1>
            <div class="current-pic">
                <label>Current Picture:</label><br>
                {current_pic}
            </div>
            <form method="POST" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="name">Name:</label>
                    <input type="text" id="name" name="name" value="{user[1]}" required>
                </div>
                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" value="{user[2]}" required>
                </div>
                <div class="form-group">
                    <label for="profile_picture">New Profile Picture:</label>
                    <input type="file" id="profile_picture" name="profile_picture" accept=".png,.jpg,.jpeg,.gif">
                </div>
                <button type="submit" class="btn">Update User</button>
                <a href="/users" class="btn btn-secondary">Cancel</a>
            </form>
        </div>
    </body>
    </html>
    '''

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    if user:
        if user[3]:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], user[3])
            if os.path.exists(file_path):
                os.remove(file_path)
        
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        
        send_email("User Deleted", f"User {user[1]} was deleted")
    
    conn.close()
    return redirect(url_for('users'))

if __name__ == '__main__':
    print("Starting Flask app...")
    init_db()
    
    # Get port from environment (for deployment)
    import os
    port = int(os.environ.get('PORT', 5000))
    
    app.run(debug=False, host='0.0.0.0', port=port)