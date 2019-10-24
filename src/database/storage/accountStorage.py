'''
    File name: accountStorage.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from settings import logger
from database.storage.storageManager import Connection
import datetime

def getKeyAddress(publicKey: str) -> str:
    """Calculate RIPEMD"""
    # TODO: calculate publicKey
    return publicKey

class AccountStorageError(Exception):
    pass

class AccountStorage(object):
    """Class for interaction between code structure and database"""
    _publicKeyAddress = None
    _publicKey = None
    _validUntil = None
    _SOD = None
    _isValid = None

    def __init__(self, publicKey: str, validUntil: datetime, SOD: str):
        """Initialization object"""
        self.publicKeyAddress = getKeyAddress(publicKey)
        self.publicKey = publicKey
        self.validUntil = validUntil
        self.SOD = SOD
        self.isValid = True

    def setIsValid(self, isValid: bool):
        """Set validation"""
        self.isValid = isValid

    def getPublicKeyAddress(self) -> str:
        """Return public key address"""
        return self.publicKeyAddress

    def getSOD(self) -> str:
        """Return SOD from object"""
        return self.SOD

    def getIsValid(self) -> bool:
        """Return isValid from object"""
        return self.isValid

    def getValidUntil(self) -> datetime:
        """Return isValid from object"""
        return self.validUntil


def writeToDB_account(publicKey: str, validUntil: datetime, SOD: str, connection: Connection) -> str:
    """Write to database with ORM"""
    try:
        logger.info("Writing account object to database. Public key: " + publicKey +
                    "; Valid until: " + str(validUntil) +
                    "; SOD: " + SOD)
        accS = AccountStorage(publicKey, validUntil, SOD)
        connection.getSession().add(accS)
        connection.getSession().commit()

        return accS.getPublicKeyAddress()
    except Exception as e:
        raise AccountStorageError("Problem with writing the object: " + e)

def readFromDBwithPublicKeyAddress_account(publicKeyAddress: str, connection: Connection) -> AccountStorage:
    """Read from database with ORM"""
    try:
        logger.info("Writing account object to database. Public key address: " + publicKeyAddress)
        result = connection.getSession().query(AccountStorage).filter(AccountStorage.publicKeyAddress == publicKeyAddress).all()

        if len(result) == 0:
            logger.info("Item not found in database or time limit exceeded")
            raise AccountStorageError("Item not found in database or time limit exceeded")

        return result[0]
    except Exception as e:
        raise AccountStorageError("Problem with reading from object: " + e)

def readFromDBwithPublicKey_account(publicKey: str, connection: Connection) -> AccountStorage:
    """Read from database row with given public key"""
    try:
        logger.info("Read account object from database. Public key: " + publicKey)
        return readFromDBwithPublicKeyAddress_account(getKeyAddress(publicKey), connection)
    except Exception as e:
        raise AccountStorageError("Problem with reading from object: " + e)
