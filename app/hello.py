import string
from flask import Flask, render_template, request, make_response, redirect
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import markdown
from collections import deque
from passlib.hash import argon2
import sqlite3
import time
import bleach
import random
import re

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

app.secret_key = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"

DATABASE = "./sqlite3.db"
def restore_db():
    print("[*] Init database!")
    sq = sqlite3.connect(DATABASE)
    sql = sq.cursor()
    sql.execute("CREATE TABLE IF NOT EXISTS user (id INTEGER PRIMARY KEY, username VARCHAR(32), password VARCHAR(128));")
    sql.execute("CREATE TABLE IF NOT EXISTS login_attempts (id INTEGER PRIMARY KEY, username VARCHAR(32), count INTEGER);")
    sql.execute(
        "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, username VARCHAR(32), note VARCHAR(256), pictureURL VARCHAR(256), isPublic INTEGER, isProtected INTEGER, password VARCHAR(128));")
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
        if argon2.verify(password, user.password):
            time.sleep(0.5)
            login_user(user)
            return redirect('/hello')
        else:
            #db = sqlite3.connect(DATABASE)
            #sql = db.cursor()
            #sql_query = "SELECT count(*) FROM login_attempts WHERE username = ?"
            #sql.execute(sql_query, (username,))
            #result = sql.fetchone()[0]
            #if result == 0:
                #sql_query = "INSERT INTO login_attempts (username, count) VALUES (?, ?);"
                #sql.execute(sql_query, (username, 0,))
            #else:
            #db.commit()
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
        lowercase_count = 0
        uppercase_count = 0
        punctuation_count = 0
        digit_count = 0
        sql_query = "SELECT count(*) FROM user WHERE username = ?"
        sql.execute(sql_query, (username,))
        result = sql.fetchone()[0]
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
            sql_query = "INSERT INTO user (username, password) VALUES (?, ?);"
            sql.execute(sql_query, (username, hash, ))
           # sql.execute(
            #    f"INSERT INTO user (username, password) VALUES ('{username}', '{argon2.using(salt= bytes(''.join(random.choices(population = string.ascii_letters, k = random.randint(10,15))), 'ascii')).hash(password)}');")
            db.commit()
            return redirect('/')

@app.route("/new_password", methods=['GET', 'POST'])
def new_password():
    if request.method == 'GET':
        return render_template("new_password.html")
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        re_email = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if (re.fullmatch(re_email, email)):
            print(f"Użytkownik poprosił o zmianę hasła, wysłałabym mu link: https://link_do_zmiany_hasla.pl na adres e-mail: '{email}'")
            return "Link do zmiany hasła został wysłany."
        else:
            return "Podano nieprawidłowy adres email."

@app.route("/hello", methods=['GET'])
@login_required
def hello():
    if request.method == 'GET':
        print(current_user.id)
        username = current_user.id
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql_query = "SELECT id FROM notes WHERE username == ?"
        sql.execute(sql_query, (username,))
        #sql.execute(f"SELECT id FROM notes WHERE username == '{username}'")
        notes = sql.fetchall()
        return render_template("hello.html", username=username, notes=notes)

@app.route("/render", methods=['POST'])
@login_required
def render():
    picture_url = request.form.get("picture_url")
    url = request.form.get("url")
    md = bleach.clean(request.form.get("markdown", ""), tags=['a','b','i','h1','h2','h3','h4','h5','br'])
    rendered = markdown.markdown(md)
    username = current_user.id
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql_query = "INSERT INTO notes (username, note, pictureURL) VALUES (?, ?, ?);"
    sql.execute(sql_query, (username, rendered, picture_url,))
    #sql.execute(f"INSERT INTO notes (username, note) VALUES ('{username}', '{rendered}')")
    db.commit()
    return render_template("markdown.html", rendered=rendered, picture_url=picture_url)


@app.route("/render/<rendered_id>")
@login_required
def render_old(rendered_id):
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql_query = "SELECT username, note, pictureURL FROM notes WHERE id == ?"
    sql.execute(sql_query, (rendered_id,))
    #sql.execute(f"SELECT username, note FROM notes WHERE id == {rendered_id}")
    try:
        username, rendered, picture_url = sql.fetchone()
        if username != current_user.id:
            return "Access to note forbidden", 403
        return render_template("markdown.html", rendered=rendered, picture_url=picture_url)
    except:
        return "Note not found", 404


if __name__ == "__main__":
    print(__name__)
    app.run("0.0.0.0", 5000)
