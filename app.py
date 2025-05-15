from flask import Flask, request, jsonify, render_template, redirect, url_for, session, Response, flash
import sqlite3
import bcrypt
import os
import threading
import time
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from mimetypes import guess_type
from flask_wtf.csrf import CSRFProtect, CSRFError
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

class Config:
    """Configuration settings for the application."""
    
    def __init__(self):
        # Define paths for database files - OUTSIDE WEB ROOT
        # Using Windows paths through WSL's /mnt/c/ mapping
        self.WINDOWS_DOCUMENTS = "/mnt/c/Users/switz/Documents"  # Update with your Windows username
        self.DB_DIR = os.path.join(self.WINDOWS_DOCUMENTS, "CloudProjectDataBases")
        
        # Create the directory if it doesn't exist
        os.makedirs(self.DB_DIR, exist_ok=True)
        
        # Define database paths with .db extension
        self.USER_DB = os.path.join(self.DB_DIR, "users.db")  # User authentication database
        self.FILES_DB = os.path.join(self.DB_DIR, "files.db")  # File management database
        
        # For uploads, also use Windows paths through WSL
        self.WINDOWS_DESKTOP = "/mnt/c/Users/switz/Desktop"  # Update with your Windows username
        self.APP_ROOT = os.path.join(self.WINDOWS_DESKTOP, "Personal-Projects", "CloudProject")
        
        # File upload settings
        self.UPLOAD_FOLDER = os.path.join(self.APP_ROOT, 'uploads')
        self.ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'csv'}
        self.MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
        
        # Secret key from .env file
        self.SECRET_KEY = os.getenv('SECRET_KEY')
        if not self.SECRET_KEY:
            raise ValueError("SECRET_KEY not found in .env file. Please set this required environment variable.")


class DatabaseInitializer:
    """Handles database initialization and table creation."""
    
    def __init__(self, config):
        self.config = config
    
    def initialize_all(self):
        """Initialize all database tables."""
        self.initialize_user_database()
        self.initialize_files_database()
        self.create_permissions_table()
        self.create_failed_login_table()
        self.create_ip_block_table()
    
    def initialize_user_database(self):
        """Create users table if it doesn't exist."""
        connection = sqlite3.connect(self.config.USER_DB)
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
        print(f"Users table created or already exists at {self.config.USER_DB}")
    
    def initialize_files_database(self):
        """Create files table if it doesn't exist."""
        connection = sqlite3.connect(self.config.FILES_DB)
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
        print(f"Files table created or already exists at {self.config.FILES_DB}")
    
    def create_permissions_table(self):
        """Create file_permissions table if it doesn't exist."""
        connection = sqlite3.connect(self.config.FILES_DB)
        c = connection.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS file_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            owner_username TEXT NOT NULL,
            shared_username TEXT NOT NULL,
            permission_type TEXT NOT NULL,
            created_date TEXT NOT NULL,
            FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE,
            UNIQUE(file_id, shared_username)
        )
        """)
        connection.commit()
        connection.close()
        print(f"File permissions table created or already exists at {self.config.FILES_DB}")
    
    def create_failed_login_table(self):
        """Create failed_logins table if it doesn't exist."""
        connection = sqlite3.connect(self.config.USER_DB)
        c = connection.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS failed_logins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            email TEXT NOT NULL,
            attempt_time TEXT NOT NULL
        )
        """)
        connection.commit()
        connection.close()
        print(f"Failed logins table created or already exists at {self.config.USER_DB}")
    
    def create_ip_block_table(self):
        """Create ip_blocks table if it doesn't exist."""
        connection = sqlite3.connect(self.config.USER_DB)
        c = connection.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS ip_blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            block_reason TEXT NOT NULL,
            blocked_until TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """)
        connection.commit()
        connection.close()
        print(f"IP blocks table created or already exists at {self.config.USER_DB}")


class SecurityManager:
    """Manages security-related functionality like IP blocking and failed logins."""
    
    def __init__(self, config):
        self.config = config
    
    def is_ip_blocked(self, ip):
        """Check if an IP address is currently blocked."""
        try:
            # Check if the IP is whitelisted (for future admin use)
            if self.is_ip_whitelisted(ip):
                return False, None
                
            connection = sqlite3.connect(self.config.USER_DB)
            c = connection.cursor()
            
            # Check explicit blocks first
            c.execute("""
            SELECT block_reason, blocked_until FROM ip_blocks 
            WHERE ip_address = ? AND blocked_until > datetime('now')
            """, (ip,))
            block_info = c.fetchone()
            
            if block_info:
                # IP is explicitly blocked
                reason, until = block_info
                connection.close()
                return True, (reason, until)
            
            # Check for too many failed attempts
            c.execute("""
            SELECT COUNT(*) FROM failed_logins 
            WHERE ip_address = ? AND attempt_time > datetime('now', '-30 minute')
            """, (ip,))
            recent_failures = c.fetchone()[0]
            connection.close()
            
            # 7+ failures in 30 minutes causes a block
            if recent_failures >= 7:
                # Block the IP
                self.block_ip(ip, f"Too many failed login attempts ({recent_failures} in 30 minutes)", 60) # 60 minutes = 1 hour
                return True, (f"Too many failed login attempts ({recent_failures} in 30 minutes)", 
                              (datetime.now() + timedelta(minutes=60)).strftime("%Y-%m-%d %H:%M:%S"))
            
            return False, None
            
        except Exception as e:
            print(f"Error checking if IP is blocked: {str(e)}")
            return False, None
    
    def is_ip_whitelisted(self, ip):
        """Check if an IP address is whitelisted (exempt from blocking)."""
        # For future use with admin IPs
        # Currently just a placeholder
        return False
    
    def block_ip(self, ip, reason, minutes):
        """Block an IP address for a specified number of minutes."""
        try:
            connection = sqlite3.connect(self.config.USER_DB)
            c = connection.cursor()
            
            # Calculate the expiration time
            blocked_until = (datetime.now() + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
            
            # Insert or replace the block
            c.execute("""
            INSERT OR REPLACE INTO ip_blocks 
            (ip_address, block_reason, blocked_until, created_at) 
            VALUES (?, ?, ?, datetime('now'))
            """, (ip, reason, blocked_until))
            
            connection.commit()
            connection.close()
            
            print(f"Blocked IP {ip} until {blocked_until}: {reason}")
            return True
        except Exception as e:
            print(f"Error blocking IP: {str(e)}")
            return False
    
    def unblock_ip(self, ip):
        """Manually unblock an IP address (for admin use)."""
        try:
            connection = sqlite3.connect(self.config.USER_DB)
            c = connection.cursor()
            
            # Delete the block
            c.execute("DELETE FROM ip_blocks WHERE ip_address = ?", (ip,))
            
            # Optionally clear failed login history
            c.execute("DELETE FROM failed_logins WHERE ip_address = ?", (ip,))
            
            connection.commit()
            connection.close()
            
            return True
        except Exception as e:
            print(f"Error unblocking IP: {str(e)}")
            return False
    
    def track_failed_login(self, ip, email):
        """Record a failed login attempt."""
        try:
            connection = sqlite3.connect(self.config.USER_DB)
            c = connection.cursor()
            c.execute("""
            INSERT INTO failed_logins (ip_address, email, attempt_time)
            VALUES (?, ?, datetime('now'))
            """, (ip, email))
            connection.commit()
            connection.close()
        except Exception as e:
            print(f"Error tracking failed login: {str(e)}")
    
    def cleanup_failed_logins(self):
        """Remove old failed login records."""
        try:
            connection = sqlite3.connect(self.config.USER_DB)
            c = connection.cursor()
            # Get count before deletion
            c.execute("SELECT COUNT(*) FROM failed_logins WHERE attempt_time < datetime('now', '-7 day')")
            count_to_delete = c.fetchone()[0]
            # Delete records older than 7 days
            c.execute("DELETE FROM failed_logins WHERE attempt_time < datetime('now', '-7 day')")
            connection.commit()
            # Log the cleanup
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{current_time}] Cleaned up {count_to_delete} failed login records older than 7 days")
            
            connection.close()
            return count_to_delete
        except Exception as e:
            print(f"Error cleaning up failed logins: {str(e)}")
            return 0
    
    def cleanup_ip_blocks(self):
        """Remove expired IP blocks."""
        try:
            connection = sqlite3.connect(self.config.USER_DB)
            c = connection.cursor()
            
            # Delete expired blocks
            c.execute("DELETE FROM ip_blocks WHERE blocked_until < datetime('now')")
            removed_count = c.rowcount
            
            connection.commit()
            connection.close()
            
            if removed_count > 0:
                print(f"Cleaned up {removed_count} expired IP blocks")
            
            return removed_count
        except Exception as e:
            print(f"Error cleaning up IP blocks: {str(e)}")
            return 0
    
    def scheduled_cleanup(self):
        """Run cleanup task in a background thread every 7 days."""
        while True:
            try:
                # Sleep until next cleanup
                time.sleep(7 * 24 * 60 * 60)  # 7 days in seconds
                
                # Perform cleanup
                cleanup_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{cleanup_time}] Running scheduled cleanup...")
                
                failed_logins_count = self.cleanup_failed_logins()
                ip_blocks_count = self.cleanup_ip_blocks()
                
                print(f"[{cleanup_time}] Cleanup complete. Removed {failed_logins_count} old login records and {ip_blocks_count} expired IP blocks")
                
            except Exception as e:
                print(f"Error in scheduled cleanup: {str(e)}")
                # Sleep for a while before retrying
                time.sleep(60 * 60)  # 1 hour
    
    def run_initial_cleanup(self):
        """Run an initial cleanup on startup."""
        print("Running initial cleanup...")
        cleanup_count = self.cleanup_failed_logins()
        ip_blocks_count = self.cleanup_ip_blocks()
        print(f"Initial cleanup complete. Removed {cleanup_count} old login records and {ip_blocks_count} expired IP blocks")
    
    def start_cleanup_thread(self):
        """Start the background cleanup thread."""
        cleanup_thread = threading.Thread(target=self.scheduled_cleanup, daemon=True)
        cleanup_thread.start()
        print("Background cleanup thread started")


class UserManager:
    """Handles user-related operations like authentication and registration."""
    
    def __init__(self, config):
        self.config = config
    
    def register_user(self, username, email, password):
        """Register a new user."""
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        connection = sqlite3.connect(self.config.USER_DB)
        c = connection.cursor()
        try:
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                      (username, email, hashed))
            connection.commit()
            connection.close()
            return True, None
        except sqlite3.IntegrityError:
            connection.close()
            return False, "Username or Email already exists!"
    
    def authenticate_user(self, email, password):
        """Authenticate a user by email and password."""
        connection = sqlite3.connect(self.config.USER_DB)
        c = connection.cursor()
        
        # Check if the email exists
        c.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
        email_exists = c.fetchone()[0] > 0
        
        if not email_exists:
            connection.close()
            return False, "Email not found"
        
        # Get user details
        c.execute("SELECT id, username, password FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        connection.close()
        
        # Check password hash format
        password_hash = user[2]
        
        # Try to decode if it's a string (might be stored as string instead of bytes)
        if isinstance(password_hash, str):
            try:
                # Try to convert string hash to bytes
                password_hash = password_hash.encode('utf-8')
            except Exception as e:
                print(f"Error converting hash: {str(e)}")
                return False, "Internal error verifying password"
        
        try:
            # Try to check password
            password_matches = bcrypt.checkpw(password.encode('utf-8'), password_hash)
            
            if password_matches:
                return True, {"id": user[0], "username": user[1]}
            else:
                return False, "Incorrect password"
                
        except Exception as e:
            print(f"Error checking password: {str(e)}")
            return False, "Error verifying password"
    
    def user_exists(self, username):
        """Check if a username exists."""
        connection = sqlite3.connect(self.config.USER_DB)
        c = connection.cursor()
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        connection.close()
        return user is not None
    
    def get_users_by_search(self, current_username, query=None, limit=10):
        """Get a list of users, optionally filtered by a search query."""
        connection = sqlite3.connect(self.config.USER_DB)
        c = connection.cursor()
        
        if query:
            c.execute("""
            SELECT username FROM users 
            WHERE username != ? AND username LIKE ? 
            ORDER BY username LIMIT ?
            """, (current_username, f'%{query}%', limit))
        else:
            c.execute("""
            SELECT username FROM users 
            WHERE username != ? 
            ORDER BY username LIMIT ?
            """, (current_username, limit))
        
        users = [user[0] for user in c.fetchall()]
        connection.close()
        return users


class FileManager:
    """Handles file operations like uploading, downloading, and sharing."""
    
    def __init__(self, config):
        self.config = config
    
    def allowed_file(self, filename):
        """Check if a file has an allowed extension."""
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in self.config.ALLOWED_EXTENSIONS
    
    def validate_file_size(self, file):
        """Check if a file is within the size limit."""
        file.seek(0, 2)  # Go to the end of the file
        file_size = file.tell()  # Get current position (file size)
        file.seek(0)  # Go back to the beginning
        return file_size <= self.config.MAX_FILE_SIZE, file_size
    
    def get_user_files(self, username):
        """Get files owned by a user."""
        connection = sqlite3.connect(self.config.FILES_DB)
        c = connection.cursor()
        c.execute("SELECT id, filename, size, upload_date FROM files WHERE username = ?", (username,))
        own_files = c.fetchall()
        connection.close()
        return own_files
    
    def get_shared_files(self, username):
        """Get files shared with a user."""
        connection = sqlite3.connect(self.config.FILES_DB)
        c = connection.cursor()
        c.execute("""
        SELECT f.id, f.filename, f.size, f.upload_date, f.username, p.permission_type 
        FROM files f 
        JOIN file_permissions p ON f.id = p.file_id 
        WHERE p.shared_username = ?
        """, (username,))
        shared_files = c.fetchall()
        connection.close()
        return shared_files
    
    def save_file(self, username, file):
        """Save an uploaded file to disk and database."""
        user_dir = os.path.join(self.config.UPLOAD_FOLDER, username)
        os.makedirs(user_dir, exist_ok=True)
        
        if not file or file.filename == '':
            return False, "No file selected"
        
        # Validate file extension
        if not self.allowed_file(file.filename):
            return False, "File type not allowed. Please upload a supported file type (txt, pdf, images, office documents)."
        
        # Validate file size
        is_valid_size, file_size = self.validate_file_size(file)
        if not is_valid_size:
            size_mb = file_size / (1024 * 1024)
            return False, f"File is too large ({size_mb:.2f} MB). Maximum size is 10 MB."
        
        # Save file
        filename = secure_filename(file.filename)
        path = os.path.join(user_dir, filename)
        
        if os.path.exists(path):
            return False, f"A file with name '{filename}' already exists. Please rename your file."
        
        try:
            file.save(path)
            
            # Save file info to database
            connection = sqlite3.connect(self.config.FILES_DB)
            c = connection.cursor()
            c.execute("""
            INSERT INTO files (username, filename, size, upload_date) 
            VALUES (?, ?, ?, datetime('now'))
            """, (username, filename, os.path.getsize(path)))
            connection.commit()
            connection.close()
            
            return True, "File uploaded successfully!"
        except Exception as e:
            print(f"Error saving file: {str(e)}")
            return False, f"Error saving file: {str(e)}"
    
    def verify_file_access(self, file_id, filename, username):
        """Verify if a user has access to a file."""
        connection = sqlite3.connect(self.config.FILES_DB)
        c = connection.cursor()
        
        # Check if the user is the owner of the file
        c.execute("SELECT username FROM files WHERE id = ? AND filename = ?", (file_id, filename))
        file_owner = c.fetchone()
        
        if not file_owner:
            connection.close()
            return False, None, "File not found."
        
        # Determine file owner for path construction
        if file_owner[0] == username:
            # User is the owner
            connection.close()
            return True, file_owner[0], None
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
                connection.close()
                return False, None, "You don't have permission to access this file."
            
            connection.close()
            return True, permission[0], None
    
    def get_file_data(self, owner_username, filename):
        """Get file data for download."""
        user_dir = os.path.join(self.config.UPLOAD_FOLDER, owner_username)
        filepath = os.path.join(user_dir, filename)
        
        if not os.path.normpath(filepath).startswith(os.path.normpath(user_dir)):
            return None, "Access denied."
        
        if not os.path.exists(filepath):
            return None, "File not found."
        
        try:
            with open(filepath, 'rb') as f:
                file_data = f.read()
            
            mimetype = guess_type(filepath)[0] or 'application/octet-stream'
            file_size = os.path.getsize(filepath)
            
            return {"data": file_data, "mimetype": mimetype, "size": file_size}, None
        except Exception as e:
            print(f"Error reading file: {str(e)}")
            return None, "Error reading file."
    
    def delete_file(self, file_id, filename, username):
        """Delete a file."""
        # Verify if user owns file
        connection = sqlite3.connect(self.config.FILES_DB)
        c = connection.cursor()
        c.execute("SELECT id FROM files WHERE id = ? AND filename = ? AND username = ?", (file_id, filename, username))
        file = c.fetchone()
        
        if not file:
            connection.close()
            return False, "You can only delete files that you own."
        
        # Delete the file from disk
        user_dir = os.path.join(self.config.UPLOAD_FOLDER, username)
        path = os.path.join(user_dir, filename)
        if os.path.exists(path):
            os.remove(path)
        
        # Delete the file from database
        c.execute("DELETE FROM files WHERE id = ?", (file_id,))
        connection.commit()
        connection.close()
        
        return True, f"{filename} deleted successfully."
    
    def share_file(self, file_id, owner_username, shared_username):
        """Share a file with another user."""
        # Verify if user owns file
        connection = sqlite3.connect(self.config.FILES_DB)
        c = connection.cursor()
        c.execute("SELECT id FROM files WHERE id = ? AND username = ?", (file_id, owner_username))
        file = c.fetchone()
        
        if not file:
            connection.close()
            return False, "You can only share files that you own."
        
        # Create the sharing permission
        try:
            c.execute("""
                INSERT INTO file_permissions (file_id, owner_username, shared_username, permission_type, created_date) 
                VALUES (?, ?, ?, 'access', datetime('now'))
            """, (file_id, owner_username, shared_username))
            connection.commit()
            connection.close()
            return True, f"File shared with {shared_username} successfully."
        except sqlite3.IntegrityError:
            connection.close()
            return False, f"File is already shared with {shared_username}."
    
    def get_file_shares(self, file_id, owner_username):
        """Get users a file is shared with."""
        connection = sqlite3.connect(self.config.FILES_DB)
        c = connection.cursor()
        
        # Verify the file exists and user is the owner
        c.execute("SELECT id, filename FROM files WHERE id = ? AND username = ?", (file_id, owner_username))
        file = c.fetchone()
        
        if not file:
            connection.close()
            return None, None, "You can only view sharing details for files that you own."
        
        # Get sharing details
        c.execute("""
            SELECT shared_username, created_date 
            FROM file_permissions 
            WHERE file_id = ? AND owner_username = ? 
            ORDER BY created_date DESC
        """, (file_id, owner_username))
        shared_users = c.fetchall()
        
        connection.close()
        return file, shared_users, None
    
    def unshare_file(self, file_id, owner_username, shared_username):
        """Remove sharing access for a user."""
        connection = sqlite3.connect(self.config.FILES_DB)
        c = connection.cursor()
        
        # Verify the file exists and user is the owner
        c.execute("SELECT id FROM files WHERE id = ? AND username = ?", (file_id, owner_username))
        file = c.fetchone()
        
        if not file:
            connection.close()
            return False, "You can only manage sharing for files that you own."
        
        # Remove the sharing permission
        c.execute("""
            DELETE FROM file_permissions 
            WHERE file_id = ? AND owner_username = ? AND shared_username = ?
        """, (file_id, owner_username, shared_username))
        connection.commit()
        connection.close()
        
        return True, f"Sharing with {shared_username} has been removed."
    
    def remove_my_access(self, file_id, username):
        """Allow a user to remove their own access to a shared file."""
        connection = sqlite3.connect(self.config.FILES_DB)
        c = connection.cursor()
        
        # Check if this file is shared with this user
        c.execute("""
            SELECT fp.owner_username, f.filename 
            FROM file_permissions fp
            JOIN files f ON fp.file_id = f.id
            WHERE fp.file_id = ? AND fp.shared_username = ?
        """, (file_id, username))
        share_info = c.fetchone()
        
        if not share_info:
            connection.close()
            return False, "You don't have access to this file or it doesn't exist."
        
        owner_username = share_info[0]
        filename = share_info[1]
        
        # Remove the sharing permission
        c.execute("""
            DELETE FROM file_permissions 
            WHERE file_id = ? AND owner_username = ? AND shared_username = ?
        """, (file_id, owner_username, username))
        connection.commit()
        connection.close()
        
        return True, f"Your access to '{filename}' has been removed."


# Initialize Flask application
def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Initialize configuration
    config = Config()
    
    # Configure app
    app.config['SECRET_KEY'] = config.SECRET_KEY
    app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER
    
    # Ensure upload directory exists
    os.makedirs(config.UPLOAD_FOLDER, exist_ok=True)
    
    # Initialize CSRF protection
    csrf = CSRFProtect(app)
    
    # Initialize rate limiter
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://",
    )
    
    # Initialize managers
    db_initializer = DatabaseInitializer(config)
    security_manager = SecurityManager(config)
    user_manager = UserManager(config)
    file_manager = FileManager(config)
    
    # Initialize databases
    db_initializer.initialize_all()
    
    # Run initial cleanup
    security_manager.run_initial_cleanup()
    
    # Start background cleanup thread
    security_manager.start_cleanup_thread()
    
    # Register routes
    @app.route('/')
    def home():
        return redirect(url_for('login'))
    
    @app.route("/register", methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            
            success, error = user_manager.register_user(username, email, password)
            if success:
                return redirect(url_for('login'))
            else:
                return error
        
        return render_template('register.html')
    
    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit("5 per minute, 20 per hour", error_message="Too many login attempts. Please try again later.")
    def login():
        ip = get_remote_address()
        
        # Check if IP is blocked
        is_blocked, block_info = security_manager.is_ip_blocked(ip)
        if is_blocked:
            reason, until = block_info
            formatted_time = datetime.strptime(until, "%Y-%m-%d %H:%M:%S").strftime("%I:%M %p on %B %d, %Y")
            flash(f"Access blocked until {formatted_time}: {reason}", "error")
            return render_template('login.html'), 403
        
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            
            success, result = user_manager.authenticate_user(email, password)
            
            if success:
                session['user_id'] = result["id"]
                session['username'] = result["username"]
                # Reset rate limit on successful login (optional)
                # Note: Don't pass get_remote_address() as it's handled internally
                limiter.reset()
                return redirect(url_for('dashboard'))
            else:
                # Track failed login attempt
                security_manager.track_failed_login(ip, email)
                flash(f"Login failed: {result}", "error")
            
        return render_template('login.html')
    
    @app.route('/check_db_path')
    def check_db_path():
        results = {
            "db_path": config.DB_DIR,
            "user_db": config.USER_DB,
            "files_db": config.FILES_DB,
            "path_exists": os.path.exists(config.DB_DIR),
            "user_db_exists": os.path.exists(config.USER_DB),
            "files_db_exists": os.path.exists(config.FILES_DB),
            "users": []
        }
        
        # If the user database exists, check its content
        if os.path.exists(config.USER_DB):
            try:
                connection = sqlite3.connect(config.USER_DB)
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
    
    @app.route('/dashboard', methods=['GET'])
    def dashboard():
        # Check if the user is logged in
        username = session.get('username')
        if not username:
            return redirect(url_for('login'))
        
        # Create user directory if it doesn't exist
        user_dir = os.path.join(config.UPLOAD_FOLDER, username)
        os.makedirs(user_dir, exist_ok=True)
        
        # Get user's personal files and shared files
        own_files = file_manager.get_user_files(username)
        shared_files = file_manager.get_shared_files(username)
        
        return render_template('dashboard.html', own_files=own_files, shared_files=shared_files, username=username)
    
    @app.route('/upload_file', methods=['POST'])
    def upload_file():
        username = session.get('username')
        if not username:
            return redirect(url_for('login'))
        
        file = request.files.get('file')
        success, message = file_manager.save_file(username, file)
        
        if success:
            flash(message, "success")
        else:
            flash(message, "error")
        
        return redirect(url_for('dashboard'))
    
    @app.route('/download/<int:file_id>/<path:filename>')
    def download_file(file_id, filename):
        if 'username' not in session:
            return redirect(url_for('login'))
        
        username = session['username']
        
        # Check if the user has permission to download this file
        has_access, owner_username, error = file_manager.verify_file_access(file_id, filename, username)
        
        if not has_access:
            flash(error, "error")
            return redirect(url_for('dashboard'))
        
        # Get file data
        file_data, error = file_manager.get_file_data(owner_username, filename)
        
        if error:
            flash(error, "error")
            return redirect(url_for('dashboard'))
        
        # Return file response
        response = Response(
            file_data["data"], 
            mimetype=file_data["mimetype"], 
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Length': str(file_data["size"])
            }
        )
        return response
    
    @app.route('/delete/<int:file_id>/<path:filename>', methods=['POST'])
    def delete_file(file_id, filename):
        username = session.get('username')
        if not username:
            return redirect(url_for('login'))
        
        success, message = file_manager.delete_file(file_id, filename, username)
        
        if success:
            flash(message, "success")
        else:
            flash(message, "error")
        
        return redirect(url_for('dashboard'))
    
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
        if not user_manager.user_exists(shared_username):
            flash(f"User '{shared_username}' does not exist.", "error")
            return redirect(url_for('dashboard'))
        
        # Share the file
        success, message = file_manager.share_file(file_id, username, shared_username)
        
        if success:
            flash(message, "success")
        else:
            flash(message, "error")
        
        # Redirect to the file shares page for better UX
        return redirect(url_for('file_shares', file_id=file_id))
    
    @app.route('/list_users', methods=['GET'])
    def list_users():
        username = session.get('username')
        if not username:
            return jsonify({'error': 'Not logged in'}), 401
        
        # Get search query
        query = request.args.get('query', '')
        
        # Get matching users
        users = user_manager.get_users_by_search(username, query)
        
        return jsonify({'users': users})
    
    @app.route('/file_shares/<int:file_id>', methods=['GET'])
    def file_shares(file_id):
        username = session.get('username')
        if not username:
            return redirect(url_for('login'))
        
        # Get file sharing details
        file, shared_users, error = file_manager.get_file_shares(file_id, username)
        
        if error:
            flash(error, "error")
            return redirect(url_for('dashboard'))
        
        return render_template('file_shares.html', file=file, shared_users=shared_users)
    
    @app.route('/unshare_file/<int:file_id>/<string:shared_username>', methods=['POST'])
    def unshare_file(file_id, shared_username):
        username = session.get('username')
        if not username:
            return redirect(url_for('login'))
        
        success, message = file_manager.unshare_file(file_id, username, shared_username)
        
        if success:
            flash(message, "success")
        else:
            flash(message, "error")
        
        return redirect(url_for('file_shares', file_id=file_id))
    
    @app.route('/remove_my_access/<int:file_id>', methods=['POST'])
    def remove_my_access(file_id):
        username = session.get('username')
        if not username:
            return redirect(url_for('login'))
        
        success, message = file_manager.remove_my_access(file_id, username)
        
        if success:
            flash(message, "success")
        else:
            flash(message, "error")
        
        return redirect(url_for('dashboard'))
    
    @app.route('/admin/blocked_ips', methods=['GET'])
    def admin_blocked_ips():
        # This is a placeholder for future admin functionality
        # We'll check for admin status here in the future
        
        if not session.get('user_id'):
            return redirect(url_for('login'))
        
        # For now, just redirect non-admins to dashboard
        return redirect(url_for('dashboard'))
    
    @app.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))
    
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        return render_template('csrf_error.html', error=e.description), 400
    
    @app.errorhandler(429)
    def ratelimit_handler(e):
        flash("Too many login attempts. Please try again later.", "error")
        return render_template('login.html'), 429
    
    # Print WSL to Windows path mapping information
    print("\nWSL TO WINDOWS PATH MAPPING:")
    print(f"WSL is accessing Windows files through the /mnt/c/ path")
    print(f"Database files are stored at: {config.DB_DIR}")
    print(f"USER_DB path: {config.USER_DB}")
    print(f"FILES_DB path: {config.FILES_DB}")
    print(f"Upload folder: {config.UPLOAD_FOLDER}")
    
    return app


# Main entry point
if __name__ == '__main__':
    app = create_app()
    print("Flask app is starting in debug mode.")
    app.run(debug=True)