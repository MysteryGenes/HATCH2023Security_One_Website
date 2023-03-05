# Imports
from passlib.hash import sha256_crypt
import json
import string
from random import *
from datetime import datetime
USER_FILE = "test.json"
LOG_FILE = "UserLogs.json"


# ----- User Class and Related ----- #
class User:
    username: string = ""
    name: string = ""
    passwordhash: string = ""
    access: int = ""


    def __init__(self, userobject: object = None, username: string = None, name: string = None, email: string = None, passwordhash: string = None, access: int = None):
        #  Checks to see if the input is via Object or individual values
        if not userobject:
            self.username = username
            self.name = name
            self.email = email
            self.passwordhash = passwordhash
            self.access = access
        else:
            self.username = userobject['username']
            self.name = userobject['name']
            self.email = userobject['email']
            self.passwordhash = userobject['passwordhash']
            self.access = userobject['access']

    
    def AsObject(self):
        {
            "username": self.username,
            "name": self.name,
            "email": self.email,
            "passwordhash": self.passwordhash,
            "access": self.access
        }


# ---- Helpers ----- #
def getUsers():
    users = []

    with open(USER_FILE, "r") as file:
        raw_users = json.load(file)
        for user in raw_users:
            users.append(User(userobject=user))

    return users


def writeUsers(users: list[User]):
    pass


# ----- Checks ----- #
# Checking the inputed username and password against
def Login(username, password, ip):
    users = getUsers()

    for user in users:
        if user.username == username:
            #  Get the hash of the inputted password to compare to the stored one
            seededPasswordHash = sha256_crypt.hash(f"{password}{user.seed}")
            correct_password = sha256_crypt.verify(user.password, seededPasswordHash)

            if correct_password:
                # TODO: Log user login success
                return {"success": True, "user": user}
            else:
                # TODO: Log user login failure
                # TODO: Remove the '(but user was found)' if this message is ever shown to the user
                return {"success": False, "message": "Password was Incorrect (but user was found)"}
    
    # TODO: Log user login failure
    return {"success": False, "messsage": "No user found with that username"}

    if "Just so that I can collapse this all" == "":
        pass
        # --- NO LONGER NEEDED ---
        """# # Iteration through each userID
        # for key in InfoFile["userID"].keys():
        #     # Testing if inputed user information if correct through hashs
        #     if sha256_crypt.verify(InfoFile["userID"][key]["seed"]+Password, InfoFile["userID"][key]["Password"]):
        #         # Runs when its verifies
        #         now = datetime.now()
        #         current_time = now.strftime("%H:%M:%S")
        #         with open(LogFilepath, "r") as TimeFile:
        #             # json_object = json.load(openfile)
        #             TimeFileOpen = json.load(TimeFile)
                    
        #         NameofUser = TimeFileOpen["userID"][key]["name"]
        #         TimeRecord = {
        #             "Username": Username,
        #             "Name": NameofUser,
        #             "Time": current_time
        #         }

        #         TimeFileOpen.update(TimeRecord)

        #         json_objecttime = json.dumps(TimeFileOpen, indent=1)

        #         with open(LogFilepath, "w") as outfileTime:
        #             outfileTime.write(json_objecttime)

        #         return TimeFileOpen["userID"][key]
        #     else:
        #         # Runs when its not correct
        #         return None"""
# -- end function --


def Signup(username, name, email, password):
    #  Generate the seed
    seed = "".join(random.choices(string.ascii_letters + string.punctuation + string.digits, k=5))
    #  Hash the password with the seed
    seededPasswordHash = sha256_crypt.hash(f"{password}{seed}")

    users = getUsers()

    # Backup checks in case the first ones fail
    if IsUsernameTaken(username):
        # TODO: Log missed check
        return {"success": False, "message": "Email was taken, check failed somewhere."}

    if IsEmailTaken(email):
        # TODO: Log missed check
        return {"success": False, "message": "Email was taken, check failed somewhere."}

    # Creates new user object to append to the list of users
    new_user = {
        "username": username,
        "password": seededPasswordHash,
        "access": 0,
        "name": name,
        "email": email,
        "seed": seed
    }

    users.append(User(userobject=new_user))
    writeUsers(users)

    return {"success": True, "user": new_user}


# ----- Checks -----
def IsUsernameTaken(username):
    users = getUsers()

    for user in users:
        if user.username == username:
            return False

    return True


def IsEmailTaken(email):
    users = getUsers()

    for user in users:
        if user.email == email:
            return False

    return True
