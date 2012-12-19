class MtGoxError(Exception):
    pass

class CredentialError(Exception):
    pass

class RightError(Exception):
    def __init__(self, message, right=None, kind=None, arg=None):
        self.msg = "Need %s rights to use %s %s" % (right, kind, arg)
        Exception.__init__(self, message)

class TokenizationError(Exception):
    pass

class DaemonError(Exception):
    pass

class InputError(Exception):
    def __init__(self, message, arg=None, kind=None):
        if arg:
            self.msg = "Invalid %s:" % (kind if kind else "argument")
        else:
            self.msg = message
        self.arg = [arg]
        Exception.__init__(self, message)