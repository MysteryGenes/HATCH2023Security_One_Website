from flask import Flask, redirect, url_for, request, session, flash, render_template, jsonify, request, send_file, make_response
from wtforms import Form, StringField, PasswordField, validators
from functools import wraps
from werkzeug.utils import secure_filename
#from Crypto.PublicKey import RSA
#from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import io
from io import BytesIO

import os

from passlib.hash import sha256_crypt

from LoginSigninFunctions import login_b, signup_b, get_users, is_email_taken, is_username_taken, User, is_code_valid
import data
import gzip

import os
import json

# import rsa

app = Flask(__name__)

UPLOAD_FOLDER = './uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# @app.after_request
# def add_header(response):
#     response.headers['Content-Encoding'] = 'gzip'
#     response.headers['Vary'] = 'Accept-Encoding'
#     if response.status_code != 204 and response.status_code != 304:
#         response_data = response.get_data()
#         gzipped_data = gzip.compress(response_data)
#         response.set_data(gzipped_data)
#         response.headers['Content-Length'] = len(gzipped_data)
#     return response
# DATA = data.Data()


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


def is_level_1(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session['access'] >= 1:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized', 'danger')
            return redirect(url_for('mainpage'))
    
    return wrap


# ----- Form Classes -----
class CreateUserForm(Form):
    name = StringField('Name', [
        validators.DataRequired(message='Fill out the name field'),
    ])
    username = StringField('Username', [
        validators.DataRequired(message='Fill out the username field'),
    ])
    email = StringField('Email', [
        validators.DataRequired(message='Fill out the email field'),
    ])
    password = PasswordField('Password', [
        validators.DataRequired(message='Fill out the password field'),
        validators.length(
            12, 64, message='Minimum password length is 12, max is 64')
    ])
    confirm_password = PasswordField('Confirm Password', [
        validators.DataRequired(message='Fill out the confirm password field'),
        validators.length(12, 64, message='Passwords do not match'),
        validators.EqualTo('password', message='Passwords do not match')
    ])
    code = StringField('Access Code', [
        validators.DataRequired(
            message="A code is required to join. Please contact an admin.")
    ])


class LoginForm(Form):
    username = StringField('Username', [
        validators.DataRequired(message="Fill out the username")
    ])
    password = PasswordField('Password', [
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
@is_logged_in
def about():
    return render_template('about.html')


@app.route('/adminmainpage')
@is_logged_in
@is_level_1
def admin_main_page():
    logs = get_logs()
    users = get_users()
    users_as_json = [user.as_object() for user in users]

    if request.method == 'POST':
        for user in users:
            if changeduser.username == user.username:
                user.change_access(changeduser.access)
                flash('User access level changed', 'success')
                return redirect(url_for('admin_main_page'))

    return render_template('adminmainpage.html', logs=logs, UData=users_as_json)


@app.route('/contact')
@is_logged_in
def contact():
    return render_template('contact.html')


@app.route('/profile')
@is_logged_in
def profile():
    return render_template('profile.html')


@app.route('/settings')
@is_logged_in
def settings():
    return render_template('settings.html')


@app.route('/mainpage')
@is_logged_in
def mainpage():
    uploads_dir = "./uploads"
    uploads_files = os.listdir(uploads_dir)
    return render_template('mainpage.html', uploads_files=uploads_files)


@app.route('/help')
@is_logged_in
def help():
    return render_template('help.html')


@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('mainpage'))
    return redirect(url_for('login'))


@app.route('/upload', methods=['POST'])
@is_level_1
def upload():
    file = request.files['file']
    filename = secure_filename(file.filename)

    # Save the file to disk
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    flash('File Successfully Uploaded', 'success')
    return redirect(url_for('admin_main_page'))
    


@app.route('/download')
@is_logged_in
def download():
    filename = request.args.get('filename')
    if not filename:
        return 'Error: no filename specified'

    path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.isfile(path):
        return 'Error: file not found'

    # Compress the file using gzip
    with open(path, 'rb') as f_in:
        compressed_data = BytesIO()
        with gzip.GzipFile(fileobj=compressed_data, mode='wb') as f_out:
            f_out.write(f_in.read())
        compressed_data.seek(0)

    # Return the compressed file as a download attachment
    response = make_response(compressed_data.getvalue())
    response.headers.set('Content-Type', 'application/octet-stream')
    response.headers.set('Content-Encoding', 'gzip')
    response.headers.set('Content-Disposition', 'attachment', filename=filename + '.gz')
    return response


def get_logs():
    with open('UserLogs.json', 'r') as file:
        logs = json.load(file)
    return logs


def get_UData():
    with open('test.json', 'r') as file:
        get_UData = json.load(file)
    return get_UData


if __name__ == '__main__':
    app.secret_key = 'thi5i54v3ry5up3r53cr3tk3y*(@$)(!*#^%*&^UFHP*@(#Y$*&_Y&fpaw38ryp8934'
    # context = ('ssl_context/server.cert', 'ssl_context/server.key')
    # app.run(host='0.0.0.0', port=8080, ssl_context=context, debug=True)
    app.run(host='0.0.0.0', port=8080, debug=True)
