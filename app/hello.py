import string
from flask import Flask, render_template, request, make_response, redirect
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
import markdown
from collections import deque
from passlib.hash import argon2
import sqlite3
import time
import bleach
import random
import re

csrf = CSRFProtect()
login_manager = LoginManager()
DATABASE = "./sqlite3.db"
app = Flask(__name__)
app.secret_key = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"
csrf.init_app(app)
login_manager.init_app(app)

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy']="default-src 'self'; img-src * data:;"
    return response

def restore_db():
    print("[*] Init database!")
    sq = sqlite3.connect(DATABASE)
    sql = sq.cursor()
    sql.execute("CREATE TABLE IF NOT EXISTS user (id INTEGER PRIMARY KEY, username VARCHAR(32) NOT NULL, email VARCHAR(128) NOT NULL, password VARCHAR(1024) NOT NULL);")
    sql.execute("CREATE TABLE IF NOT EXISTS login_attempts (id INTEGER PRIMARY KEY, username VARCHAR(32) NOT NULL, count INTEGER DEFAULT 0);")
    sql.execute(
        "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, username VARCHAR(32) NOT NULL, note VARCHAR(1024) NOT NULL, isPublic INTEGER DEFAULT 0, isProtected INTEGER DEFAULT 0, password VARCHAR(128), datetime TIMESTAMP DEFAULT CURRENT_TIMESTAMP);")
    sq.commit()
    sq.close()

restore_db()

class User(UserMixin):
    pass

@login_manager.user_loader
def user_loader(username):
    if username is None:
        return None

    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql_query = "SELECT username, password FROM user WHERE username = ?"
    sql.execute(sql_query, (username,))
    row = sql.fetchone()
    try:
        username, password = row
    except:
        return None
    user = User()
    user.id = username
    user.password = password
    return user

@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = user_loader(username)
    return user
recent_users = deque(maxlen=3)

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("index.html")
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = user_loader(username)
        if user is None:
            return "Nieprawidłowy login lub hasło", 401
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql_query = "SELECT count(*) FROM login_attempts WHERE username = ?"
        sql.execute(sql_query, (username,))
        result = sql.fetchone()[0]
        if result == 0:
            sql_query = "INSERT INTO login_attempts (username) VALUES (?);"
            sql.execute(sql_query, (username,))
            db.commit()
        sql_query = "SELECT count FROM login_attempts WHERE username = ?"
        sql.execute(sql_query, (username,))
        count = sql.fetchone()[0]
        if count > 3:
            return "Zbyt dużo nieudanych prób logowania. Konto zostało zablokowane.", 401
        if argon2.verify(password, user.password):
            time.sleep(0.5)
            login_user(user)
            sql_query = "UPDATE login_attempts SET count = 0 WHERE username = ?"
            sql.execute(sql_query, (username,))
            db.commit()
            return redirect('/hello')
        else:
            sql_query = "UPDATE login_attempts SET count = ? WHERE username = ?"
            sql.execute(sql_query, (count+1, username,))
            db.commit()
            return "Nieprawidłowy login lub hasło", 401

@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template("register.html")
    if request.method == 'POST':
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        re_email = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        lowercase_count = 0
        uppercase_count = 0
        punctuation_count = 0
        digit_count = 0
        sql_query = "SELECT count(*) FROM user WHERE username = ?"
        sql.execute(sql_query, (username,))
        result = sql.fetchone()[0]
        if len(username) <= 0:
            return "Musisz podać nazwę użytkownika."
        if len(username) > 32:
            return "Podana nazwa użytkownika jest zbyt długa."
        if not (re.fullmatch(re_email, email)):
            return "Podano nieprawidłowy adres email."
        if result > 0:
            return "Wybierz inną nazwę użytkownika."
        if len(password) < 8:
            return "Hasło jest zbyt krótkie (powinno zawierać co najmniej 8 znaków)"
        for char in password:
            if char.islower() == True:
                lowercase_count = lowercase_count + 1
            if char.isupper() == True:
                uppercase_count = uppercase_count + 1
            if char.isdigit() == True:
                digit_count = digit_count + 1
            if char in string.punctuation:
                punctuation_count = punctuation_count + 1
        if lowercase_count == 0 or uppercase_count == 0 or digit_count == 0 or punctuation_count == 0:
            return "Hasło musi zawierać co najmniej jedną małą literę, wielką literę, cyfrę i znak specjalny."
        else:
            hash = argon2.using(
                salt=bytes(''.join(random.choices(population=string.ascii_letters, k=random.randint(10, 15))),
                           'ascii')).hash(password)
            sql_query = "INSERT INTO user (username, email, password) VALUES (?, ?, ?);"
            sql.execute(sql_query, (username, email, hash, ))
            db.commit()
            return redirect('/')

@app.route("/new_password", methods=['GET', 'POST'])
def new_password():
    if request.method == 'GET':
        return render_template("new_password.html")
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql_query = "SELECT count(*) FROM user WHERE username = ? and email = ?"
        sql.execute(sql_query, (username,email,))
        result = sql.fetchone()[0]
        re_email = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if not (re.fullmatch(re_email, email)):
            return "Podano nieprawidłowy adres email."
        if result == 1:
            print(f"Użytkownik '{username}' poprosił o zmianę hasła, wysłałabym mu link: https://link_do_zmiany_hasla.pl na adres e-mail: '{email}'")
            return "Link do zmiany hasła został wysłany."
        else:
            return "Podano nieprawidłowe dane."


@app.route("/hello", methods=['GET', 'POST'])
@login_required
def hello():
    if request.method == 'GET':
        username = current_user.id
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql_query = "SELECT id, isPublic, isProtected, datetime, username FROM notes WHERE username == ? OR isPublic = 1"
        sql.execute(sql_query, (username,))
        notes = sql.fetchall()
        return render_template("hello.html", username=username, notes=notes)
    if request.method == 'POST':
        username = current_user.id
        note_id = request.form.get("note_id")
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        if "submit_publish" in  request.form:
            sql_query = "UPDATE notes SET isPublic = 1 WHERE username = ? AND id = ?"
            sql.execute(sql_query, (username, note_id,))
        elif "submit_unpublish" in request.form:
            sql_query = "UPDATE notes SET isPublic = 0 WHERE username = ? AND id = ?"
            sql.execute(sql_query, (username, note_id,))
        db.commit()
        db.close()
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql_query = "SELECT id, isPublic, isProtected, datetime, username FROM notes WHERE username == ? OR isPublic = 1"
        sql.execute(sql_query, (username,))
        notes = sql.fetchall()
        return render_template("hello.html", username=username, notes=notes)


@app.route("/render", methods=['POST'])
@login_required
def render():
    md = bleach.clean(request.form.get("markdown", ""), tags=['a','p','b','i','h1','h2','h3','h4','h5','br'])
    rendered = markdown.markdown(md)
    username = current_user.id
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql_query = "INSERT INTO notes (username, note) VALUES (?, ?);"
    sql.execute(sql_query, (username, rendered,))
    db.commit()
    return render_template("markdown.html", rendered=rendered)


@app.route("/render/<rendered_id>")
@login_required
def render_old(rendered_id):
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql_query = "SELECT username, note FROM notes WHERE id == ?"
    sql.execute(sql_query, (rendered_id,))
    try:
        username, rendered = sql.fetchone()
        if username != current_user.id:
            return "Access to note forbidden", 403
        return render_template("markdown.html", rendered=rendered)
    except:
        return "Note not found", 404


if __name__ == "__main__":
    print(__name__)
    app.run("0.0.0.0", 5000)
