'''
    File name: accountStorage.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from settings import logger

from database.storage.storageManager import Connection
from database.utils import *
from APIservice.proto.user import UserId

from pymrtd import ef
from pymrtd.pki.keys import AAPublicKey, SignatureAlgorithm

from datetime import datetime
from typing import Union



class AccountStorageError(Exception):
    pass

class AccountStorage(object):
    """Class for interaction between code structure and database"""
    _uid = None
    _publicKey = None
    _validUntil = None
    _SOD = None
    _isValid = None

    def __init__(self, uid: str, aaPublicKey: str, sigAlgo: Union[str, None], validUntil: datetime, sod: str):
        """Initialization object"""
        assert isinstance(uid, str)
        assert isinstance(aaPublicKey, str)
        assert isinstance(sigAlgo, (str, type(None)))
        assert isinstance(sod, str)

        self.uid         = uid
        self.aaPublicKey = aaPublicKey
        self.sigAlgo     = sigAlgo
        self.validUntil  = validUntil
        self.sod         = sod
        self.isValid     = True

    def setIsValid(self, isValid: bool):
        """Set validation"""
        self.isValid = isValid

    def getUserId(self) -> UserId:
        """Return User ID """
        return str2uid(self.uid)

    def getAAPublicKey(self) -> AAPublicKey:
        return AAPublicKey.load(b64decode(self.aaPublicKey))

    def getSigAlgo(self) -> Union[SignatureAlgorithm, None]:
        if self.sigAlgo is None:
            return None
        return SignatureAlgorithm.load(b64decode(self.sigAlgo))

    def getSOD(self) -> ef.SOD:
        """Return SOD from object"""
        return ef.SOD.load(b64decode(self.sod))

    def getIsValid(self) -> bool:
        """Return isValid from object"""
        return self.isValid

    def getValidUntil(self) -> datetime:
        """Return isValid from object"""
        return self.validUntil


def writeToDB_account(publicKey: AAPublicKey, sigAlog: Union[SignatureAlgorithm, None], validUntil: datetime, sod: ef.SOD, connection: Connection) -> UserId:
    """Write to database with ORM"""
    try:
        assert isinstance(publicKey, AAPublicKey)
        assert isinstance(sigAlog, (SignatureAlgorithm, type(None)))
        assert isinstance(sod, ef.SOD)

        if sigAlog is not None:
            sigAlog = b64encode(sigAlgo.dump())

        uid  = UserId.fromAAPublicKey(publicKey)
        accS = AccountStorage(
            uid2str(uid),
            b64encode(publicKey.dump()), 
            sigAlog,
            validUntil,
            b64encode(sod)
        )

        logger.debug("Writing account object to database. uid={} valid_until={}".format(uid2str(uid), validUntil))
        connection.getSession().add(accS)
        connection.getSession().commit()
        return uid

    except Exception as e:
        raise AccountStorageError("Problem with writing the object: " + str(e))

def readFromDBwithUid_account(uid: UserId, connection: Connection) -> AccountStorage:
    """Read from database with ORM"""
    try:
        logger.debug("Writing account object to database. uid={}", uid2str(uid))
        result = connection.getSession() \
            .query(AccountStorage) \
            .filter(AccountStorage.uid == uid2str(uid)) \
            .all()

        if len(result) == 0:
            logger.warning("Item not found in database or time limit exceeded")
            raise AccountStorageError("Item not found in database or time limit exceeded.")

        return result[0]
    except Exception as e:
        raise AccountStorageError("Problem with reading from object: " + str(e))

def readFromDBwithPublicKey_account(publicKey: AAPublicKey, connection: Connection) -> AccountStorage:
    """Read from database row with given public key"""
    try:
        return readFromDBwithUid_account(UserId.fromAAPublicKey(publicKey), connection)
    except Exception as e:
        raise AccountStorageError("Problem with reading from object: " + str(e))
