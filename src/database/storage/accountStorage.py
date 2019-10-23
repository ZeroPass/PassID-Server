import datetime
import hashlib

class AccountStorageError(Exception):
    pass

class AccountStorage(object):
    """Class for interaction between code structure and database"""
    _accountID = None
    _publicKey = None
    _validUntil = None
    _SOD = None
    _isValid = None

    def __init__(self, publicKey: bytes, validUntil: datetime, SOD: bytes):
        """Initialization object"""
        self.accountID = hashlib.md5(str(publicKey))
        self.publicKey = publicKey
        self.validUntil = validUntil
        self.SOD = SOD
        self.isValid = True

    def setIsValid(self, isValid):
        """Set validation"""
        self.isValid = isValid

    def getSOD(self) -> bytes:
        """Return SOD from object"""
        return self.SOD

    def getIsValid(self) -> bool:
        """Return isValid from object"""
        return self.isValid

