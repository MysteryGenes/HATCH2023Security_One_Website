from flask import Flask, redirect, url_for, request, session, flash, render_template, jsonify, request, send_file
from wtforms import Form, StringField, PasswordField, validators
from functools import wraps
from werkzeug.utils import secure_filename
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

from passlib.hash import sha256_crypt

from LoginSigninFunctions import login_b, signup_b, get_users, is_email_taken, is_username_taken, User, is_code_valid
import data

import os
import json

# import rsa

app = Flask(__name__)
DATA = data.Data()

UPLOAD_FOLDER = './uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# generating rsa key pair
key = RSA.generate(2048)
with open('private.pem','wb') as f:
    f.write(key.export_key())
cipher = PKCS1_OAEP.new(key.publickey())


# ----- Wraps -----
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized', 'danger')
            return redirect(url_for('login'))

    return wrap


def is_not_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            flash('You are already logged in!', 'success')
            return redirect(url_for('mainpage'))
        else:
            return f(*args, **kwargs)

    return wrap


# ----- Form Classes -----
class CreateUserForm(Form):
    name = StringField('name', [
        validators.DataRequired(message='Fill out the name field'),
    ])
    username = StringField('username', [
        validators.DataRequired(message='Fill out the username field'),
    ])
    email = StringField('email', [
        validators.DataRequired(message='Fill out the email field'),
    ])
    password = PasswordField('password', [
        validators.DataRequired(message='Fill out the password field'),
        validators.length(
            12, 64, message='Minimum password length is 12, max is 64')
    ])
    confirm_password = PasswordField('confirm_password', [
        validators.DataRequired(message='Fill out the confirm password field'),
        validators.length(12, 64, message='Passwords do not match'),
        validators.EqualTo('password', message='Passwords do not match')
    ])
    code = StringField('code', [
        validators.DataRequired(
            message="A code is required to join. Please contact an admin.")
    ])


class LoginForm(Form):
    username = StringField('username', [
        validators.DataRequired(message="Fill out the username")
    ])
    password = PasswordField('password', [
        validators.DataRequired(message="Fill out the password form")
    ])


# ----- Main App -----
@app.route('/signup', methods=['GET', 'POST'])
@is_not_logged_in
def signup():
    form = CreateUserForm(request.form)

    if request.method == 'POST' and form.validate():
        # USE THESE VARIALBES
        username = form.username.data
        name = form.name.data
        email = form.email.data
        password = form.password.data
        code = form.code.data

        if is_username_taken(username):
            flash("Username is taken", "danger")
            return render_template('create.html', form=form)
        if is_email_taken(email):
            flash("Email is taken", "danger")
            return render_template('create.html', form=form)
        if not is_code_valid(code, DATA):
            flash("Invalid code. Please reach out to an admin.", "danger")
            return render_template('create.html', form=form)

        create_user = signup_b(username, name, email, password, code, DATA, request.remote_addr)

        if create_user['success']:
            print(email, form.password.data)
            return redirect(url_for('login'))
        else:
            flash("An error has occurred. Please try again.", 'danger')
            return render_template('create.html', form=form)

    return render_template('create.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@is_not_logged_in
def login():
    form = LoginForm(request.form)

    if request.method == "POST" and form.validate():
        username = form.username.data
        passwordhash = sha256_crypt.hash(form.password.data)

        print(username, form.password.data, f"SHA256: {passwordhash}")

        # Run check function here, Ideally hash the password before sending through to function but not required.
        user = login_b(username, form.password.data, request.remote_addr)
        if user['success']:
            session['username'] = user['user'].username
            session['name'] = user['user'].name
            session['email'] = user['user'].email
            session['access'] = user['user'].access
            session['logged_in'] = True

            flash('You are now logged in', 'success')
            # return redirect(url_for('dashboard'))

            return redirect(url_for('mainpage'))
        else:
            flash("Invalid Login. Please try again.", "danger")
            return redirect(url_for('login'))

    return render_template('login.html', form=form)



@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


@app.route('/logsomething')
@is_logged_in
def logsomething():
    return redirect(url_for('logout'))


@app.route('/checksession')
def checksession():
    print(session)

    return f"<p>logged_in: {session['logged_in']}, username: {session['username']}, name: {session['name']}, email: {session['email']}, access: {session['access']}</p>"


@app.route('/about')
# @is_logged_in
def about():
    return render_template('about.html')

@app.route('/williammitchell')
def williammitchell():
    return render_template('williammitchell.html')


@app.route('/contact')
# @is_logged_in
def contact():
    return render_template('contact.html')


@app.route('/profile')
# @is_logged_in
def profile():
    return render_template('profile.html')


@app.route('/adminmainpage')
# @is_logged_in
def adminmainpage():
    return render_template('adminmainpage.html')


@app.route('/settings')
# @is_logged_in
def settings():
    return render_template('settings.html')


@app.route('/mainpage')
@is_logged_in
def mainpage():
    return render_template('mainpage.html')


@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('mainpage'))
    return redirect(url_for('login'))


# Code for admin JS thing
@app.route('/AdminParsing')
def get_Admindata():
    NameList = []
    # Opens json file for user info
    with open("test.json", "r") as openUsersFile:
        UsersInfoFile = json.load(openUsersFile)
    # Opens json file for admin logs
    with open("UserLogs.json", "r") as openLogsFile:
        LogsForFile = json.load(openLogsFile)
    for key in UsersInfoFile.keys():
        NameList.append(UsersInfoFile[key]["name"] + ":" + UsersInfoFile[key]["access"])

    return render_template('index.html', data=UsersInfoFile)



@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    filename = secure_filename(file.filename)
    file_contents = file.read()
    encrypted_contents=cipher.encrypt(file_contents)
    with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), 'wb') as f:
        f.write(encrypted_contents)
    return 'File uploaded successfully'


@app.route('/download')
def download():
    filename = request.args.get('filename')
    if not filename:
        return 'Error: no filename specified'
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.isfile(path):
        return 'Error: file not found'
    # Read the encrypted file contents and decrypt with RSA
    with open(path, 'rb') as f:
        encrypted_contents = f.read()
    decrypted_contents = key.decrypt(encrypted_contents)
    # Return the decrypted contents as a file attachment
    return send_file(
        io.BytesIO(decrypted_contents),
        mimetype='application/octet-stream',
        as_attachment=True,
        attachment_filename=filename
    )


if __name__ == '__main__':
    app.secret_key = 'thi5i54v3ry5up3r53cr3tk3y*(@$)(!*#^%*&^UFHP*@(#Y$*&_Y&fpaw38ryp8934'
    app.run(host='0.0.0.0', port=8080, debug=True)
