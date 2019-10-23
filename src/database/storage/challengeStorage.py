
class ChallengeStorageError(Exception):
    pass

class ChallengeStorage(object):
    """Class for interaction between code structure and database"""
    #_id = None
    #_challenge = None

    def __init__(self):
        self.id = "kva3"
        self.challenge = 9

    def create(self) -> dict:
        """Creating challenge"""
        bitSize = 64
        #self.challenge = uuid4().int >> bitSize
        #self.id = hashlib.md5(str(self.challenge).encode('utf-8'))
        self.id = "bula"
        self.challenge = 657
        return {self.id: self.challenge}

    def checkSignature(self, signature) -> bool:
        """Check if signature is correct"""
        #TODO: write function
        return True

    def check(self, signature) -> bool:
        """Returns true if signature is correct, false viceversa"""
        if signature == None:
            raise ChallengeStorageError("Signature is empty")

        if self.checkSignature(signature) == False:
            raise ChallengeStorageError("Signature is not correct")
        return True
