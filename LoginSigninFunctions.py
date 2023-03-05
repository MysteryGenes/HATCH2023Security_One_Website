# Imports
from passlib.hash import sha256_crypt
import json
import string
import random
from datetime import datetime

USER_FILE = "test.json"
LOG_FILE = "UserLogs.json"


# ----- User Class and Related ----- #
class User:
    username: string = ""
    name: string = ""
    email: string = ""
    password: string = ""
    access: int = ""
    salt: string = ""

    def __init__(self, userobject: object = None, username: string = None, name: string = None, email: string = None, password: string = None, access: int = None, salt: string = None):
        #  Checks to see if the input is via Object or individual values
        if not userobject:
            self.username = username
            self.name = name
            self.email = email
            self.password = password
            self.access = access
            self.salt = salt
        else:
            self.username = userobject['username']
            self.name = userobject['name']
            self.email = userobject['email']
            self.password = userobject['password']
            self.access = userobject['access']
            self.salt = userobject['salt']
    
    def as_object(self):
        return {
            "username": self.username,
            "name": self.name,
            "email": self.email,
            "password": self.password,
            "access": self.access,
            "salt": self.salt
        }


# ---- Helpers ----- #
def get_users():
    users = []

    with open(USER_FILE, "r") as file:
        raw_users = json.load(file)
        for user in raw_users:
            users.append(User(userobject=user))

    return users


def write_users(users: list[User]):
    with open(USER_FILE, "w") as file:
        json.dump([user.as_object() for user in users], file, indent=1)


# ----- Checks ----- #

# Do not change these function names. They are set this way for a reason.
# Checking the inputted username and password against
def login_b(username, password, ip):
    users = get_users()

    for user in users:
        if user.username == username:
            print(username, user.as_object())
            #  Get the hash of the inputted password to compare to the stored one
            correct_password = sha256_crypt.verify(f"{password}{user.salt}", user.password)

            print(correct_password)
            if correct_password:
                # TODO: Log user login success
                log_user(user.username, user.name, "Success", ip)

                return {"success": True, "user": user}
            else:
                # TODO: Log user login failure
                
                log_user(user.username, user.name, "Failed", ip)
                
                # TODO: Remove the '(but user was found)' if this message is ever shown to the user
                return {"success": False, "message": "Password was Incorrect (but user was found)"}
    
    print("fail")
    # TODO: Log user login failure
    return {"success": False, "messsage": "No user found with that username"}


def signup_b(username, name, email, password, code, data, ip):
    #  Generate the salt
    salt = "".join(random.choices(string.ascii_letters + string.punctuation + string.digits, k=5))
    #  Hash the password with the salt
    saltedpassword = sha256_crypt.hash(f"{password}{salt}")

    users = get_users()

    # Backup checks in case the first ones fail
    if is_username_taken(username):
        # TODO: Log missed check
        return {"success": False, "message": "Email was taken, check failed somewhere."}

    if is_email_taken(email):
        # TODO: Log missed check
        return {"success": False, "message": "Email was taken, check failed somewhere."}

    if not is_code_valid(code, data):
        # TODO: Log missed check
        return {"success": False, "message": "Email was taken, check failed somewhere."}

    # Creates new user object to append to the list of users
    new_user = {
        "username": username,
        "name": name,
        "email": email,
        "password": saltedpassword,
        "access": 0,
        "salt": salt
    }

    data.remove_code(code)
    users.append(User(userobject=new_user))
    write_users(users)

    return {"success": True, "user": new_user}


# ----- Checks -----
def is_username_taken(username):
    users = get_users()

    for user in users:
        if user.username == username:
            return False

    return True


def is_email_taken(email):
    users = get_users()

    for user in users:
        if user.email == email:
            return False

    return True


def is_code_valid(code, data):
    return code in data.codes


def log_user(username, name, success, ip):
    logs = []
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    with open("UserLogs.json", "r") as TimeFile:
        time_file_open = json.load(TimeFile)
        for each in time_file_open:
            logs.append(each)

    new_record = {
        "Username": username,
        "Name": name,
        "Time": current_time,
        "Success": success,
        "ip": ip
    }

    logs.append(new_record)

    with open(LOG_FILE, "w") as file:
        json.dump([log for log in logs], file, indent=1)
