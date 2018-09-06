"""
CREDs file for Network user
"""

class ADUser(object):
    def __init__(self):
        self.user = "Enter Username"
        self.passwd = "Enter Password"

    def getUser(self):
        return self.user

    def getPasswd(self):
        return self.passwd

class LocalUser(object):
    def __init__(self):
        self.user = "Enter Username"
        self.passwd = "Enter Password"

    def getUser(self):
        return self.user

    def getPasswd(self):
        return self.passwd