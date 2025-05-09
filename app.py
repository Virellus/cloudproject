from flask import *
import sqlite3
import bcrypt
app = Flask(__name__)
app.secret_key = "f5mf37mrf946meap4625"
DB = "users.db"
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
        connection = sqlite3.connect(DB)
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
        connection = sqlite3.connect(DB)
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
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session: 
        return render_template('dashboard.html', username=session['username'])
    return redirect(url_for('login'))
#Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))
if __name__ == '__main__':
    app.run(debug=True)        
