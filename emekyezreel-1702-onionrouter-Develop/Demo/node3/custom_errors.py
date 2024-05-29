# this is a file containing all the errors needed for the node.py file

# message doesn't follow protocol.
class ProtocolError(Exception):
    def __init__(self, message="The message doesn't follow protocol."):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return self.message

# client send bad messages again and again
class BadClient(Exception):
    def __init__(self, message="Disconnecting client due to continuous failing in communication."):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return self.message

# fail to keep connection with the directory
class DirectoryError(Exception):
    def __init__(self, message="Directory not answering"):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return self.message
