from flask import Flask, redirect, url_for, request, session, flash, render_template, jsonify, request, send_file
from wtforms import Form, StringField, PasswordField, validators
from functools import wraps
from werkzeug.utils import secure_filename
import os

from passlib.hash import sha256_crypt

from LoginSigninFunctions import Login, Signup, getUsers

import os
import json
# import rsa

app = Flask(__name__)


UPLOAD_FOLDER = './uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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
            return redirect(url_for('login'))
        else:
            return f(*args, **kwargs)

    return wrap


# ----- Form Classes -----
class CreateUserForm(Form):
    name = StringField('name', [
        validators.DataRequired(message='Fill out the email')
    ])
    username = StringField('username', [
        validators.DataRequired(message='Fill out the username')
    ])
    email = StringField('email', [
        validators.DataRequired(message='Fill out the email')
    ])
    password = PasswordField('password', [
        validators.DataRequired(message='Fill out the password'),
        validators.length(
            12, 64, message='Minimum password length is 12, max is 64')
    ])
    code = StringField('code', [
        validators.DataRequired(
            message="A code is required to join. Please contact an admin.")
    ])


class LoginForm(Form):
    email = StringField('email', [
        validators.DataRequired(message="Fill out the email")
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
        email = form.email.data
        passwordhash = sha256_crypt.hash(form.password.data)

        print(email, form.password.data, f"SHA256: {passwordhash}")
        return redirect(url_for('login'))

    return render_template('create.html', form=form)


@app.route('/login')
@is_not_logged_in
def login():
	form = LoginForm(request.form)

	if request.method == "POST" and form.validate():
		email = form.email.data
		passwordhash = sha256_crypt.hash(form.password.data)

		print(email, form.password.data, f"SHA256: {passwordhash}")

		session['logged_in'] = True

		# Run check function here, Ideally hash the password before sending through to function but not required.
		user = Login(email, form.password.data, )		
		if user:
			session['logged_in'] = True
			session['username'] = user['username']
			session['email'] = user['email']
			session['access'] = user['access']

			return redirect(url_for('mainpage'))
		else:
			return flash("Invalid Login. Please try again.")

	return render_template('login.html')


@app.route('/about')
#@is_logged_in
def about():
  return render_template('about.html')


@app.route('/contact')
#@is_logged_in
def contact():
  return render_template('contact.html')


@app.route('/profile')
#@is_logged_in
def profile():
  return render_template('profile.html')


@app.route('/adminmainpage')
#@is_logged_in
def adminmainpage():
  return render_template('adminmainpage.html')


@app.route('/settings')
#@is_logged_in
def settings():
  return render_template('settings.html')


@app.route('/mainpage')
# @is_logged_in
def mainpage():
    return render_template('mainpage.html')


@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('mainpage'))
    return redirect(url_for('login'))


#Code for admin JS thing
#what does this do? If you want admin status, use >> x = session['access'] << and it will give you the access level as an integer from the database
#when you read this, delete
#it works anywhere in this file, just put it where you want to use the admin level

#This code is for the admin page viewing others not your users session
#Use >> getUsers() << then also, it uses dot notation not 
@app.route('/AdminParsing')
def get_Admindata():
    NameList=[]
    #Opens json file for user info
    with open("test.json", "r") as openUsersFile:
        UsersInfoFile = json.load(openUsersFile)
    #Opens json file for admin logs
    with open("UserLogs.json", "r") as openLogsFile:
        LogsForFile = json.load(openLogsFile)
    for key in UsersInfoFile["userID"].keys():
        NameList.append(UsersInfoFile["userID"][key]["Name"]+":"+UsersInfoFile["userID"][key]["Access"])

    return jsonify(NameList,LogsForFile)



@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return 'File uploaded successfully'


@app.route('/download')
def download():
    filename = request.args.get('filename')
    if not filename:
        return 'Error: no filename specified'
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.isfile(path):
        return 'Error: file not found'
    return send_file(path, as_attachment=True)
    

if __name__ == '__main__':
    app.secret_key = 'thi5i54v3ry5up3r53cr3tk3y*(@$)(!*#^%*&^UFHP*@(#Y$*&_Y&fpaw38ryp8934'
    app.run(host='0.0.0.0', port=8080, debug=True)