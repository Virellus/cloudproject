from flask import *
import sqlite3
import bcrypt
import os
from werkzeug.utils import *
from mimetypes import *

# Define paths for database files - OUTSIDE WEB ROOT
# Using Windows paths through WSL's /mnt/c/ mapping
WINDOWS_DOCUMENTS = "/mnt/c/Users/switz/Documents"  # Update with your Windows username
DB_DIR = os.path.join(WINDOWS_DOCUMENTS, "CloudProjectDataBases")

# Create the directory if it doesn't exist
os.makedirs(DB_DIR, exist_ok=True)

# Define database paths with .db extension
USER_DB = os.path.join(DB_DIR, "users.db")  # User authentication database
FILES_DB = os.path.join(DB_DIR, "files.db")  # File management database

# For uploads, also use Windows paths through WSL
WINDOWS_DESKTOP = "/mnt/c/Users/switz/Desktop"  # Update with your Windows username
APP_ROOT = os.path.join(WINDOWS_DESKTOP, "Personal-Projects", "CloudProject")

def initialize_databases():
    # Create users database
    connection = sqlite3.connect(USER_DB)
    c = connection.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)
    connection.commit()
    connection.close()
    print(f"Users table created or already exists at {USER_DB}")
    
    # Create files database
    connection = sqlite3.connect(FILES_DB)
    c = connection.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        filename TEXT NOT NULL,
        size INTEGER NOT NULL,
        upload_date TEXT NOT NULL
    )
    """)
    connection.commit()
    connection.close()
    print(f"Files table created or already exists at {FILES_DB}")

## gets called to check file type with list of approved
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'csv'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

## limits file size to 10MB
def validate_file_size(file):
    MAX_FILE_SIZE = 10 * 1024 * 1024
    file.seek(0,2)
    file_size = file.tell()
    file.seek(0)
    return file_size <= MAX_FILE_SIZE, file_size

def create_permissions_table():
    connection = sqlite3.connect(FILES_DB)
    c = connection.cursor()
    c.execute(""" CREATE TABLE IF NOT EXISTS file_permissions (id INTEGER PRIMARY KEY AUTOINCREMENT, file_id INTEGER NOT NULL, owner_username TEXT NOT NULL, shared_username TEXT NOT NULL, permission_type TEXT NOT NULL, created_date TEXT NOT NULL, FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE, UNIQUE(file_id, shared_username)) """)
    connection.commit()
    connection.close()
    print(f"File permissions table created or already exists at {FILES_DB}")

app = Flask(__name__)
# Set up the upload folder within the web root using Windows paths
# This is for uploaded files, which should remain in web app directory
upload_folder = os.path.join(APP_ROOT, 'uploads')
allowed_extensions = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app.config['upload_folder'] = upload_folder

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

app.secret_key = "f5mf37mrf946meap4625"

##HomePage
@app.route('/')
def home():
    return redirect(url_for('login'))

##Create test user route
@app.route('/create_test_user')
def create_test_user():
    try:
        connection = sqlite3.connect(USER_DB)
        c = connection.cursor()
        
        # Create users table if it doesn't exist
        c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        """)
        
        # Create a test user
        password = "test123"
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        try:
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    ("test_user", "test@example.com", hashed))
            connection.commit()
            connection.close()
            
            return f"""
            <h1>Test user created successfully</h1>
            <p>Email: test@example.com</p>
            <p>Password: test123</p>
            <p><a href="/login">Click here to login</a></p>
            """
        except sqlite3.IntegrityError:
            connection.close()
            return f"""
            <h1>Test user already exists</h1>
            <p>Email: test@example.com</p>
            <p>Password: test123</p>
            <p><a href="/login">Click here to login</a></p>
            """
    except Exception as e:
        return f"""
        <h1>Error creating test user</h1>
        <p>Error: {str(e)}</p>
        """

##Register
@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        connection = sqlite3.connect(USER_DB)
        c = connection.cursor()
        try:
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                      (username, email, hashed))
            connection.commit()
        except sqlite3.IntegrityError:
            return "Username or Email already exists!"
        connection.close()
        return redirect(url_for('login'))
    return render_template('register.html')

##Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Print debug info to help troubleshoot
        print(f"Attempting login for email: {email}")
        print(f"Using database at: {USER_DB}")
        
        connection = sqlite3.connect(USER_DB)
        c = connection.cursor()
        
        # Check if the email exists
        c.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
        email_exists = c.fetchone()[0] > 0
        print(f"Email exists in database: {email_exists}")
        
        if email_exists:
            # Get user details
            c.execute("SELECT id, username, password FROM users WHERE email = ?", (email,))
            user = c.fetchone()
            
            # Check password hash format
            password_hash = user[2]
            print(f"Password hash type: {type(password_hash).__name__}")
            print(f"Password hash: {password_hash[:10]}...") # Show just the beginning
            
            # Try to decode if it's a string (might be stored as string instead of bytes)
            if isinstance(password_hash, str):
                try:
                    # Try to convert string hash to bytes
                    password_hash = password_hash.encode('utf-8')
                    print("Converted string hash to bytes")
                except Exception as e:
                    print(f"Error converting hash: {str(e)}")
            
            try:
                # Try to check password
                password_matches = bcrypt.checkpw(password.encode('utf-8'), password_hash)
                print(f"Password check result: {password_matches}")
                
                if password_matches:
                    session['user_id'] = user[0]
                    session['username'] = user[1]
                    return redirect(url_for('dashboard'))
                else:
                    return "Login failed: incorrect password."
            except Exception as e:
                print(f"Error checking password: {str(e)}")
                return f"Login error: There was a problem verifying your password. The error is: {str(e)}"
        else:
            print(f"No user found with email: {email}")
            return "Login failed: email not found in database."
        
        connection.close()
    return render_template('login.html')

##Simple database check route
@app.route('/check_db_path')
def check_db_path():
    results = {
        "db_path": DB_DIR,
        "user_db": USER_DB,
        "files_db": FILES_DB,
        "path_exists": os.path.exists(DB_DIR),
        "user_db_exists": os.path.exists(USER_DB),
        "files_db_exists": os.path.exists(FILES_DB),
        "users": []
    }
    
    # If the user database exists, check its content
    if os.path.exists(USER_DB):
        try:
            connection = sqlite3.connect(USER_DB)
            c = connection.cursor()
            
            # Check table structure
            c.execute("PRAGMA table_info(users)")
            columns = [col[1] for col in c.fetchall()]
            results["user_table_columns"] = columns
            
            # Get user count
            c.execute("SELECT COUNT(*) FROM users")
            user_count = c.fetchone()[0]
            results["user_count"] = user_count
            
            # Get sample users (first 5)
            c.execute("SELECT id, username, email FROM users LIMIT 5")
            users = c.fetchall()
            
            # Add users to results
            for user in users:
                results["users"].append({
                    "id": user[0],
                    "username": user[1],
                    "email": user[2]
                })
            
            connection.close()
        except Exception as e:
            results["error"] = str(e)
    
    return jsonify(results)

## Dashboard
@app.route('/dashboard', methods=['GET'])
def dashboard():
    ## checks if the user is a valid user and if not kicks them back to login
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))
    user_dir = os.path.join(app.config['upload_folder'], username)
    os.makedirs(user_dir, exist_ok=True)
    
    ## gets users personal files
    connection = sqlite3.connect(FILES_DB)
    c = connection.cursor()
    c.execute("SELECT id, filename, size, upload_date FROM files WHERE username = ?", (username,))
    own_files = c.fetchall()
    
    ## get files shared with the user 
    c.execute(""" SELECT f.id, f.filename, f.size, f.upload_date, f.username, p.permission_type FROM files f JOIN file_permissions p ON f.id = p.file_id WHERE p.shared_username = ? """, (username,))
    shared_files = c.fetchall()
    connection.close()
    
    return render_template('dashboard.html', own_files=own_files, shared_files=shared_files, username=username)

## Upload file
@app.route('/upload_file', methods=['POST'])
def upload_file():
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))
    user_dir = os.path.join(app.config['upload_folder'], username)
    file = request.files.get('file')
    if not file or file.filename =='':
        flash("No file selected", "error")
        return redirect(url_for('dashboard'))
        
    ## validates file extension
    if not allowed_file(file.filename):
        flash("File type not allowed. Please upload a supported file type (txt, pdf, images, office documents).", "error")
        return redirect(url_for('dashboard'))
        
    ## validates file size ##
    ## gets file size 
    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    MAX_FILE_SIZE = 10 * 1024 * 1024
    if file_size > MAX_FILE_SIZE:
        size_mb = file_size / (1024 * 1024)
        flash(f"File is too large ({size_mb:.2f} MB). Maximum size is 10 MB.", "error")
        return redirect(url_for('dashboard'))
        
    filename = secure_filename(file.filename)
    path = os.path.join(user_dir, filename)
    
    if os.path.exists(path):
        flash(f"A file with name '{filename}' already exists. Please rename your file.", "error")
        return redirect(url_for('dashboard'))
    file.save(path)
    
    connection = sqlite3.connect(FILES_DB)
    c = connection.cursor()
    c.execute("INSERT INTO files (username, filename, size, upload_date) VALUES (?, ?, ?, datetime('now'))", (username, filename, os.path.getsize(path)))
    connection.commit()
    connection.close()
    
    flash("File uploaded successfully!", "success")
    return redirect(url_for('dashboard'))

## Download file
@app.route('/download/<int:file_id>/<path:filename>')
def download_file(file_id, filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    # Check if the user has permission to download this file
    connection = sqlite3.connect(FILES_DB)
    c = connection.cursor()
    # Check if the user is the owner of the file
    c.execute("SELECT username FROM files WHERE id = ? AND filename = ?", (file_id, filename))
    file_owner = c.fetchone()
    if not file_owner:
        flash("File not found.", "error")
        return redirect(url_for('dashboard'))
    # Determine file owner for path construction
    if file_owner[0] == username:
        # User is the owner
        owner_username = username
    else:
        # Check if the file is shared with the user
        c.execute("""
            SELECT fp.owner_username 
            FROM file_permissions fp
            JOIN files f ON fp.file_id = f.id
            WHERE fp.file_id = ? AND fp.shared_username = ? AND f.filename = ?
        """, (file_id, username, filename))
        permission = c.fetchone()
        if not permission:
            flash("You don't have permission to access this file.", "error")
            return redirect(url_for('dashboard'))
        owner_username = permission[0]
    connection.close()
    # Proceed with file download
    user_dir = os.path.join(app.config['upload_folder'], owner_username)
    filepath = os.path.join(user_dir, filename)
    if not os.path.normpath(filepath).startswith(os.path.normpath(user_dir)):
        flash("Access denied.", "error")
        return redirect(url_for('dashboard'))
    if not os.path.exists(filepath):
        flash("File not found.", "error")
        return redirect(url_for('dashboard'))
    mimetype = guess_type(filepath)[0] or 'application/octet-stream'
    try:
        with open(filepath, 'rb') as f:
            file_data = f.read()
        response = Response(
            file_data, 
            mimetype=mimetype, 
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Length': str(os.path.getsize(filepath))
            }
        )
        return response
    except Exception as e:
        print(f"Error sending file: {e}")
        flash("Error downloading file.", "error")
        return redirect(url_for('dashboard'))

## Delete file
@app.route('/delete/<int:file_id>/<path:filename>', methods=['POST'])
def delete_file(file_id, filename):
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))
    ## verify if user owns file
    connection = sqlite3.connect(FILES_DB)
    c = connection.cursor()
    c.execute("SELECT id FROM files WHERE id = ? AND filename = ? AND username = ?", (file_id, filename, username))
    file = c.fetchone()
    if not file: 
        flash("You can only delete files that you own.", "error")
        return redirect(url_for('dashboard'))
    user_dir = os.path.join(app.config['upload_folder'], username)
    path = os.path.join(user_dir, filename)
    ##delete from the file 
    if os.path.exists(path):
        os.remove(path)
    
    c.execute("DELETE FROM files WHERE id = ?", (file_id,))
    connection.commit()
    connection.close()
    flash(f"{filename} deleted successfully.", "success")
    return redirect(url_for('dashboard'))

## Share file
@app.route('/share_file/<int:file_id>', methods=['POST'])
def share_file(file_id):
    username = session.get('username')
    if not username: 
        return redirect(url_for('login'))
    # Get the user to share with 
    shared_username = request.form.get('shared_username')
    if not shared_username:
        flash("Please specify a user to share with.", "error")
        return redirect(url_for('dashboard'))
    # Verify if shared user exists
    connection = sqlite3.connect(USER_DB)
    c = connection.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (shared_username,))
    user_exists = c.fetchone()
    connection.close()
    if not user_exists:
        flash(f"User '{shared_username}' does not exist.", "error")
        return redirect(url_for('dashboard'))
    # Verify the current user owns files
    connection = sqlite3.connect(FILES_DB)
    c = connection.cursor()
    c.execute("SELECT id FROM files WHERE id = ? AND username = ?", (file_id, username))
    file = c.fetchone()
    if not file:
        flash("You can only share files that you own.", "error")
        return redirect(url_for('dashboard'))
    # Create the sharing permission - simplified to just track access
    try:
        c.execute("""
            INSERT INTO file_permissions (file_id, owner_username, shared_username, permission_type, created_date) 
            VALUES (?, ?, ?, 'access', datetime('now'))
        """, (file_id, username, shared_username))
        connection.commit()
        flash(f"File shared with {shared_username} successfully.", "success")
    except sqlite3.IntegrityError:
        flash(f"File is already shared with {shared_username}.", "warning")
    connection.close()
    # Redirect to the file shares page instead of dashboard for better UX
    return redirect(url_for('file_shares', file_id=file_id))

## List users
@app.route('/list_users', methods=['GET'])
def list_users():
    username = session.get('username')
    if not username:
        return jsonify({'error': 'Not logged in'}), 401
    # searching term 
    query = request.args.get('query', '')
    connection = sqlite3.connect(USER_DB)
    c = connection.cursor()
    ## searched for matching users
    if query:
        c.execute(""" SELECT username FROM users WHERE username != ? AND username LIKE ? ORDER BY username LIMIT 10 """, (username, f'%{query}%'))
    else:
        c.execute(""" SELECT username FROM users WHERE username != ? ORDER BY username LIMIT 10 """, (username,))
    users = [user[0] for user in c.fetchall()]
    connection.close()
    return jsonify({'users': users})

## Manage sharing permissions
@app.route('/file_shares/<int:file_id>', methods=['GET'])
def file_shares(file_id):
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))
    # Verify the current user ownership
    connection = sqlite3.connect(FILES_DB)
    c = connection.cursor()
    c.execute("SELECT id, filename FROM files WHERE id = ? AND username = ?", (file_id, username))
    file = c.fetchone()
    if not file:
        flash("You can only view sharing details for files that you own.", "error")
        return redirect(url_for('dashboard'))
    # Get sharing details - simplified to just show who has access
    c.execute("""
        SELECT shared_username, created_date 
        FROM file_permissions 
        WHERE file_id = ? AND owner_username = ? 
        ORDER BY created_date DESC
    """, (file_id, username))
    shared_users = c.fetchall()
    connection.close()
    return render_template('file_shares.html', file=file, shared_users=shared_users)

@app.route('/unshare_file/<int:file_id>/<string:shared_username>', methods=['POST'])
def unshare_file(file_id, shared_username):
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))
    # Verify the current user owns the file
    connection = sqlite3.connect(FILES_DB)
    c = connection.cursor()
    c.execute("SELECT id FROM files WHERE id = ? AND username = ?", (file_id, username))
    file = c.fetchone()
    if not file:
        flash("You can only manage sharing for files that you own.", "error")
        return redirect(url_for('dashboard'))
    # Remove the sharing permission
    c.execute(""" DELETE FROM file_permissions WHERE file_id = ? AND owner_username = ? AND shared_username = ? """, (file_id, username, shared_username))
    connection.commit()
    connection.close()
    flash(f"Sharing with {shared_username} has been removed.", "success")
    return redirect(url_for('file_shares', file_id=file_id))

@app.route('/remove_my_access/<int:file_id>', methods=['POST'])
def remove_my_access(file_id):
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))
    # Verify the file exists and is shared with the current user
    connection = sqlite3.connect(FILES_DB)
    c = connection.cursor()
    # Check if this file is actually shared with this user
    c.execute("""
        SELECT fp.owner_username, f.filename 
        FROM file_permissions fp
        JOIN files f ON fp.file_id = f.id
        WHERE fp.file_id = ? AND fp.shared_username = ?
    """, (file_id, username))
    share_info = c.fetchone()
    if not share_info:
        flash("You don't have access to this file or it doesn't exist.", "error")
        return redirect(url_for('dashboard'))
    owner_username = share_info[0]
    filename = share_info[1]
    # Remove the sharing permission
    c.execute("""
        DELETE FROM file_permissions 
        WHERE file_id = ? AND owner_username = ? AND shared_username = ?
    """, (file_id, owner_username, username))
    connection.commit()
    connection.close()
    flash(f"Your access to '{filename}' has been removed.", "success")
    return redirect(url_for('dashboard'))

##Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Ensure directories exist
    os.makedirs(upload_folder, exist_ok=True)
    os.makedirs(DB_DIR, exist_ok=True)
    
    # Print WSL to Windows path mapping information
    print("\nWSL TO WINDOWS PATH MAPPING:")
    print(f"WSL is accessing Windows files through the /mnt/c/ path")
    print(f"Database files are stored at: {DB_DIR}")
    print(f"USER_DB path: {USER_DB}")
    print(f"FILES_DB path: {FILES_DB}")
    print(f"Upload folder: {upload_folder}")
    
    # Initialize databases
    initialize_databases()
    create_permissions_table()
    
    print("Flask app is starting in debug mode.")
    app.run(debug=True)