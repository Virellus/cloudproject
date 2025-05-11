from flask import *
import sqlite3
import bcrypt
import os
from werkzeug.utils import *
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
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    print("==> Using DB path:", os.path.abspath(FILES_DB))
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))
    user_dir = os.path.join(app.config['upload_folder'], username)
    os.makedirs(user_dir, exist_ok=True)
    files = []
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
            return render_template('dashboard.html', files=files, username=username)
        connection = sqlite3.connect(FILES_DB)
        c = connection.cursor()
        c.execute("SELECT filename, size, upload_date FROM files WHERE username = ?", (username,))
        files = c.fetchall()
        connection.close()
    return render_template('dashboard.html', files=files, username=username)
##ability to add files
@app.route('/download/<filename>')
def download_file(filename):
    username = session.get('username')
    if not username: 
        return redirect(url_for('login'))
    user_dir = os.path.join(app.config['upload_folder'], username,)
    return send_from_directory(user_dir, filename, as_attachment=True)
#Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))
if __name__ == '__main__':
    app.run(debug=True)        
