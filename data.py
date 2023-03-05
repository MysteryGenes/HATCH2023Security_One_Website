import string
import random
import json


class Data:
    codes: list

    def __init__(self):
        with open("codes.json", "r") as file:
            self.codes = json.load(file)

    def __write_codes(self):
        with open("codes.json", "w") as file:
            json.dump(self.codes, file)
            return True

    def generate_code(self):
        code = "".join(random.choices(string.ascii_letters + string.punctuation + string.digits, k=6))
        self.codes.append(code)
        self.__write_codes()
        return code

    def remove_code(self, code):
        self.codes.remove(code)
        self.__write_codes()
        return True
