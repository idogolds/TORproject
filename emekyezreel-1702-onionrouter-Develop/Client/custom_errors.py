# this is a file containing all the errors needed for the node.py file


# message doesn't follow protocol.
class ProtocolError(Exception):
    def __init__(self, message="The message doesn't follow protocol.") -> None:
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return self.message
    

# node/server not responding
class TargetUnReachable(Exception):
    def __init__(self, message="Can't reach target") -> None:
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return self.message


# node didn't pass RSA verification
class NodeNotVerified(Exception):
    def __init__(self, message="Node didn't pass verification.") -> None:
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return self.message
    

# can't find directory / directory offline
class directoryUnReachable(Exception):
    def __init__(self, message="Can't find directory.") -> None:
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return self.message
    

# no node online or less than 3
class directoryNoNodes(Exception):
    def __init__(self, message="Directory return empty list.") -> None:
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return self.message
    
class ProxyErrors(Exception):
    def __init__(self, message="Proxy connection failed.", error_num=5) -> None:
        self.message = message
        self.error_num = error_num
        super().__init__(self.message)

    def __str__(self):
        return self.message
    