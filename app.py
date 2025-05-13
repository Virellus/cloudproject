from flask import *
import sqlite3
import bcrypt
import os
from werkzeug.utils import *
from mimetypes import *
## gets called to check file type with list of arrpoved
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
app = Flask(__name__)
upload_folder = 'uploads'
allowed_extensions = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app.config['upload_folder'] = upload_folder
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
app.secret_key = "f5mf37mrf946meap4625"
USER_DB = "users.db"
FILES_DB = "files.db"
##HomePage
@app.route('/')
def home():
    return redirect(url_for('login'))
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
        connection = sqlite3.connect(USER_DB)
        c = connection.cursor()
        c.execute("SELECT id, username, password FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        connection.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('dashboard'))
        else:
            return "Login failed: wring credetials"
    return render_template('login.html')
#Dashboard
"""
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    print("==> Using DB path:", os.path.abspath(FILES_DB))
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))
    user_dir = os.path.join(app.config['upload_folder'], username)
    os.makedirs(user_dir, exist_ok=True)
    ##files = []
    connection = sqlite3.connect(FILES_DB)
    c = connection.cursor()
    c.execute("SELECT filename, size, upload_date FROM files WHERE username = ?", (username,))
    files = c.fetchall()
    connection.close()
    if request.method == 'POST':
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            path = os.path.join(user_dir, filename)
            file.save(path)
            ##saving file meta data to datebase
            connection = sqlite3.connect(FILES_DB)
            c = connection.cursor()
            c.execute("INSERT INTO files (username, filename, size, upload_date) VALUES (?, ?, ?, datetime('now'))", (username, filename, os.path.getsize(path)))
            connection.commit()
            connection.close()
            flash("File uploaded successfully!", "success")
            ##return render_template('dashboard.html', files=files, username=username)
        connection = sqlite3.connect(FILES_DB)
        c = connection.cursor()
        c.execute("SELECT filename, size, upload_date FROM files WHERE username = ?", (username,))
        files = c.fetchall()
        connection.close()
    return render_template('dashboard.html', files=files, username=username)
"""
## new dashbaord?
@app.route('/dashboard', methods=['GET'])
def dashboard():
    ##print("==> Using DB path:", os.path.abspath(FILES_DB))
    ## checks if the user is a vailid user and if not kicks them back to login
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))
    user_dir = os.path.join(app.config['upload_folder'], username)
    os.makedirs(user_dir, exist_ok=True)
    connection = sqlite3.connect(FILES_DB)
    c = connection.cursor()
    c.execute("SELECT filename, size, upload_date FROM files WHERE username = ?", (username,))
    files = c.fetchall()
    connection.close()
    return render_template('dashboard.html', files=files, username=username)
## new upload?
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
    ## vailidates file extension
    if not allowed_file(file.filename):
        flash ("File type not allowed. Please upload a supported file type (txt, pdf, images, office documents).", "error")
        return redirect(url_for('dashboard'))
    ## valitates file size ##
    ## gets file size 
    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    MAX_FILE_SIZE = 10 * 1024 * 1024
    if file_size > MAX_FILE_SIZE:
        size_mb = file_size / (1024 * 1024)
        flash(f"File is too large ({size_mb:.2f} MB). Maximum size is 10 MB.", "error")
        return redirect(url_for('dashboard'))
    ##size_valid, file_size = validate_file_size(file)
    ##if not size_valid:
    ##file = request.files.get('file')
    ##if file and allowed_file(file.filename):
    filename = secure_filename(file.filename)
    path = os.path.join(user_dir, filename)
    ##file.save(path)
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


##ability to add files
@app.route('/download/<path:filename>')
def download_file(filename):
    ##username = session.get('username')
        ##return redirect(url_for('login'))
    ##filepath = os.path.join(user_dir, filename)
    ##debuging
    ##print(f"USer: {username}")
    ##print(f"Filepath: {filepath}")
    ##print(f"Filename: {filename}")
    ##if not os.path.exists(filepath):
        ##flash("File not found.", "error")
        ##return redirect(url_for('dashboard'))
    ##mimetype = guess_type(filepath)[0]
    ##return send_from_directory(user_dir, filename, as_attachment=True)
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    user_dir = os.path.join(app.config['upload_folder'], username)
    ##filename = secure_filename(filename)
    filepath = os.path.join(user_dir, filename)
    if not os.path.normpath(filepath).startswith(os.path.normpath(user_dir)):
        flash("Access denied.", "error")
        return redirect(url_for('dashboard'))
    if not os.path.exists(filepath):
        flash("File not found.", "error")
        return redirect(url_for('dashboard'))
    mimetype = guess_type(filepath)[0] or 'application/octet-stream'
    print(f"Sending file: {filepath} with mimetype {mimetype}")
    try:
        with open(filepath, 'rb') as f:
            file_data = f.read()
        response = Response(
            file_data, 
            mimetype=mimetype, 
            headers={
                'Content-Disposition': f'attachment; filenmae="{filename}"',
                'Content-Length': str(os.path.getsize(filepath))
            }
        )
        return response
    except Exception as e:
        print(f"Error sending file: {e}")
        flash("Error downloading file.", "error")
        return redirect(url_for('dashboard'))
##ability to delete files
@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))
    user_dir = os.path.join(app.config['upload_folder'], username)
    path = os.path.join(user_dir, filename)
    ##delete from the file 
    if os.path.exists(path):
        os.remove(path)
    connection = sqlite3.connect(FILES_DB)
    c = connection.cursor()
    c.execute("DELETE FROM files WHERE username = ? AND filename = ?", (username, filename))
    connection.commit()
    connection.close()
    flash(f"{filename} deleted successfully.", "sucess")
    return redirect(url_for('dashboard'))
##Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))
if __name__ == '__main__':
    print("Flask app is starting in debug mode.")
    app.run(debug=True)        
