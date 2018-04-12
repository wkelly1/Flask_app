from flask import Flask, render_template, request, flash, url_for, redirect, session
from flask_wtf import Form, RecaptchaField
from wtforms import BooleanField, validators, PasswordField, StringField
from passlib.hash import sha256_crypt
from MySQLdb import escape_string as thwart
from flask.ext.admin import Admin, BaseView, expose
from flask.ext.admin.contrib.fileadmin import FileAdmin
from flask.ext.mail import Message, Mail
import os.path as op
from functools import wraps
from dbconnect import connection
import gc
import datetime
import pygal
from collections import Counter

app = Flask(__name__)
admin = Admin(app)
mail = Mail()
path = op.join(op.dirname(__file__), 'static/test')
admin.add_view(FileAdmin(path, '/static/test', name='Static Files'))

# set the secret key.  keep this really secret:
app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'
app.WTF_CSRF_SECRET_KEY = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'
app.config['RECAPTCHA_PUBLIC_KEY'] = '6Ld14VEUAAAAACNJAmUPEAcFg1xRGSXUlN5rJSFw'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6Ld14VEUAAAAAOO5hyLVR-evTwtQVlaNQpwPcDfV'
#--mail--
app.config["MAIL_SERVER"] = "mail.btinternet.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = 'william.kelly20@btinternet.com'
app.config["MAIL_PASSWORD"] = '*********'

mail.init_app(app)

class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=3, max=25)])
    email = StringField('Email Address', [validators.Length(min=6, max=35)])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    accept_tos = BooleanField('I accept the TOS', [validators.DataRequired(message="You must accept the TOS")])
    recaptcha = RecaptchaField()

@app.route('/', methods=['GET','POST'])
def index():
    try:
        form = RegistrationForm(request.form)

        if request.method == "POST" and form.validate():
            username = form.username.data
            email = form.email.data
            password = sha256_crypt.encrypt(form.password.data)

            c, conn = connection()

            x = c.execute("SELECT * FROM users WHERE username = (%s)", (thwart(username),))

            if int(x) > 0:
                flash("That username is already taken, please choose another")
                return render_template('index.html', form=form)
            else:

                c.execute("INSERT INTO users (username, password, email, tracking) VALUES (%s, %s, %s, %s)", (
                thwart(username), thwart(password), thwart(email), thwart("/introduction-to-python-programming/"),))

                conn.commit()

                flash("Thanks for registering!")

                c.close()
                conn.close()

                gc.collect()

                session['logged_in'] = True
                session['username'] = username

                return redirect(url_for('dashboard'))

        return render_template("index.html", form=form)
    except Exception as e:
        return render_template("index.html", form=form)

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html")

@app.errorhandler(403)
def page_not_found(e):
    return render_template("403.html")

@app.errorhandler(500)
def page_not_found(e):
    return render_template("500.html")

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash("You need to login first")
            return redirect(url_for('login'))

    return wrap

@app.route('/register/', methods=['GET','POST'])
def register():
    try:

        form = RegistrationForm(request.form)

        if request.method == "POST" and form.validate():
            username = form.username.data
            email = form.email.data
            password = sha256_crypt.encrypt(form.password.data)

            c, conn = connection()

            x = c.execute("SELECT * FROM users WHERE username = (%s)",(thwart(username),))

            if int(x) > 0:
                flash("That username is already taken, please choose another")
                return render_template('register.html', form=form)
            else:


                c.execute("INSERT INTO users (username, password, email, tracking) VALUES (%s, %s, %s, %s)",(thwart(username), thwart(password), thwart(email), thwart("/introduction-to-python-programming/"),))

                conn.commit()

                flash("Thanks for registering!")

                c.close()
                conn.close()

                gc.collect()

                session['logged_in'] = True
                session['username'] = username

                return redirect(url_for('dashboard'))

        return render_template("register.html", form=form)

    except Exception as e:
        return render_template("register.html", form=form)

@app.route('/dashboard/', methods=['GET','POST'])
@login_required
def dashboard():
    try:
        if justLoggedIn == True:
            flash("Welcome, "+session['username'])
            just_logged_in = False

        return render_template("dashboard.html")
    except Exception as e:
        return render_template("dashboard.html")

@app.route('/login/', methods=['GET','POST'])
def login():
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":
            if "@" in request.form['username']:

                data = c.execute("SELECT * FROM users WHERE email = (%s)", (thwart(request.form['username']),))

                data = c.fetchone()[2]


                if sha256_crypt.verify(request.form['password'], data):
                    user = c.execute("SELECT * FROM users WHERE email = (%s)", (thwart(request.form['username']),))
                    user = c.fetchone()[1]
                    session['logged_in'] = True
                    session['username'] = user
                    dateTime = datetime.datetime.now()

                    time = c.execute("SELECT time FROM users WHERE username = (%s)",(user,))
                    time = c.fetchone()[0]

                    if time != None:
                        dateTime = str(dateTime) + '/'
                        dateTime = str(time) + str(dateTime)
                    else:
                        dateTime = '/' + str(dateTime) + '/'


                    c.execute("UPDATE users SET time = (%s) WHERE username = (%s)", (dateTime, user), )
                    conn.commit()
                    flash("You are now logged in")

                    return redirect(url_for("dashboard"))
                else:
                    error = "Invalid credentials, try again."
            else:

                data = c.execute("SELECT * FROM users WHERE username = (%s)", (thwart(request.form['username']),))

                data = c.fetchone()[2]

                if sha256_crypt.verify(request.form['password'], data):
                    user = c.execute("SELECT * FROM users WHERE username = (%s)", (thwart(request.form['username']),))
                    user = c.fetchone()[1]

                    session['logged_in'] = True
                    session['username'] = user
                    dateTime = datetime.datetime.now()

                    time = c.execute("SELECT time FROM users WHERE username = (%s)", (user,))
                    time = c.fetchone()[0]

                    if time != None:
                        dateTime = str(dateTime) + '/'
                        dateTime = str(time) + str(dateTime)
                    else:
                        dateTime = '/' + str(dateTime) + '/'
                    c.execute("UPDATE users SET time = (%s) WHERE username = (%s)", (dateTime, user),)
                    conn.commit()
                    flash("You are now logged in")


                    return redirect(url_for("dashboard"))
                else:
                    error = "Invalid credentials, try again."
        gc.collect()

        return render_template("login.html", error=error)
    except Exception as e:
        flash(e)
        return render_template("login.html", error=error)



@app.route('/signout/')
@login_required
def signout():
    session.clear()
    gc.collect()
    return redirect(url_for('index'))

@app.route('/support/', methods=['GET','POST'])
def support():
    try:
        if request.method == 'POST':
            name = request.form['name']
            email = request.form['email']
            message = request.form['message']

            msg = Message("Support", sender=email, recipients=['william.kelly20@btinternet.com'])
            msg.body = message
            mail.send(msg)


        return render_template('support.html')
    except Exception as e:
        return render_template('support.html')

@app.route('/adminLogin/', methods=['GET','POST'])
def adminLogin():
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":
            data = c.execute("SELECT * FROM users WHERE username = (%s)", (thwart(request.form['username']),))
            adminVerify = c.fetchone()[6]
            data = c.execute("SELECT * FROM users WHERE username = (%s)", (thwart(request.form['username']),))
            data = c.fetchone()[2]

            try:
                if adminVerify > 1:
                    if sha256_crypt.verify(request.form['password'], data):

                        session['logged_in'] = True
                        session['username'] = request.form['username']
                        session['admin'] = True
                        flash("You are now logged in")
                        justLoggedIn = True
                        return redirect(url_for("adminDashboard"))
                    else:
                        error = "Invalid credentials, try again."
            except:
                flash("You don't have admin privileges")

        gc.collect()

        return render_template("admin-login.html", error=error)
    except Exception as e:
        flash(e)
        return render_template("admin-login.html", error=error)

def admin_login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session and 'admin' in session:
            return f(*args, **kwargs)
        else:
            flash("You need to login first")
            return redirect(url_for('adminLogin'))

    return wrap

@app.route("/adminDashboard/", methods=['GET','POST'])
@admin_login_required
def adminDashboard():
    try:
        if request.method == 'POST':
            if request.form['submit'] == "Delete":

                selected = request.form.getlist('select')

                for i in selected:

                    c, conn = connection()
                    c.execute("DELETE FROM `users` WHERE `users`.`uid` = (%s)", (i,))
                    conn.commit()

            if request.form['submit'] == "Edit":

                selected = request.form.getlist('select')

                if len(selected) >= 1:
                    return redirect(url_for('editUser', user=selected))
                else:
                    flash("You haven't selected anything")



        c, conn = connection()
        c.execute("SELECT * FROM users")
        data = c.fetchall()
        gc.collect()

        return render_template('adminDashboard.html', data=data)
    except Exception as e:
        return render_template('adminDashboard.html', data=data)

@app.route("/adminDashboard/editUser/<user>'", methods=['GET','POST'])
@admin_login_required
def editUser(user):
    try:
        if request.method == 'POST':
            data = request.form.getlist('text')

            fixedData = [data[x:x + 6] for x in range(0, len(data), 6)]


            for data in fixedData:
                c, conn = connection()

                c.execute("UPDATE `users` SET `username` = (%s), `email` = (%s), `settings` = (%s), `tracking` = (%s), `rank` = (%s) WHERE`users`.`uid` = (%s);", (thwart(data[1]), thwart(data[2]), thwart(data[3]), thwart(data[4]), thwart(data[5]), data[0]))
                conn.commit()

            flash("Edited user")
            return redirect(url_for('adminDashboard'))

        c, conn = connection()

        user = user[1:-1]
        user = user.replace("'", "")

        user = user.split(", ")

        data = ""
        length = len(user) +1
        count=0
        for i in user:
            data = data + "uid = " + i
            if count == length-2:
                break
            else:
                data = data + " OR "
                count = count + 1

        sql = "SELECT * FROM `users` WHERE {}".format(data)
        c.execute(sql)
        data = c.fetchall()
        gc.collect()

        return render_template("editUser.html", data=data)
    except Exception as e:
        return render_template("editUser.html", data=data)

@app.route("/settings/")
def settings():
    return redirect(url_for("general"))

@app.route("/settings/general", methods=['GET','POST'])
@login_required
def general():
    try:
        if request.method == 'POST':
            email = thwart(request.form['email'])
            username = thwart(request.form['username'])


            user = session['username']
            c, conn = connection()
            data = c.execute("SELECT * FROM users WHERE username = (%s)", (user,))
            data = c.fetchone()[2]

            if sha256_crypt.verify(request.form['password'], data):
                c.execute("SELECT username FROM users")
                data = c.fetchall()
                users = []
                for i in data:
                    users.append(i[0])

                if request.form['username'] in users:
                    flash("That username is already taken!")
                else:

                    c, conn = connection()
                    c.execute("UPDATE `users` SET `username` = (%s), `email` = (%s) WHERE`users`.`username` = (%s);", (thwart(username), thwart(email), user,))
                    conn.commit()
                    session['username'] = thwart(request.form['username'])
                    flash("Updated settings")
                    return redirect(url_for('general'))
            else:
                flash("Incorrect password")

        c, conn = connection()
        user = session['username']

        c.execute("SELECT * FROM users WHERE username = (%s)", (user,))
        data = c.fetchall()
        gc.collect()
        return render_template("general.html", data=data)
    except Exception as e:
        flash(e)
        print(e)
        c, conn = connection()
        user = session['username']

        c.execute("SELECT * FROM users WHERE username = (%s)", (user,))
        data = c.fetchall()
        gc.collect()
        return render_template("general.html", data=data)
@app.route("/settings/security")
def security():
    return render_template("security.html")

@app.route("/settings/email_notifications")
def email_notifications():
    return render_template("email_notifications.html")

@app.route("/settings/interesting_info")
def interesting_info():
    try:
        user = session['username']
        c,conn = connection()
        c.execute("SELECT time FROM users WHERE username = (%s)",(user,))
        data = c.fetchone()[0]
        data = data.split("/")
        data = data[1:-1]
        newData = []
        for i in data:
             newData.append(i[0:9])
        countData = dict(Counter(newData))
        print(countData)
        print(newData)
        dates = []
        number = []
        for i, x in countData.items():
            dates.append(i)
            number.append(x)
        graph = pygal.Bar()
        graph.title = 'Time logged in'
        graph.x_labels = dates
        graph.add('No.Login times', number)

        graph_data = graph.render_data_uri()
        return render_template("interesting_info.html", graph_data=graph_data)
    except Exception as e:
        return (str(e))
    return render_template("interesting_info.html")


if __name__ == "__main__":
    app.run()
