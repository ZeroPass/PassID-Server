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

    def __init__(self, uid: UserId, sod: ef.SOD, aaPublicKey: AAPublicKey, sigAlgo: Union[SignatureAlgorithm, None], dg1: Union[ef.DG1, None], validUntil: datetime, loginCount: int = 0):
        """Initialization object"""
        assert isinstance(uid, UserId)
        assert isinstance(sod, ef.SOD)
        assert isinstance(aaPublicKey, AAPublicKey)
        assert isinstance(sigAlgo, (SignatureAlgorithm, type(None)))
        assert isinstance(dg1, (ef.DG1, type(None)))
        assert isinstance(validUntil, datetime)
        assert isinstance(loginCount, int)

        if sigAlgo is not None:
            sigAlog = sigAlgo.dump()
        if dg1 is not None:
            dg1 = dg1.dump()

        self.uid         = uid
        self.sod         = sod.dump()
        self.aaPublicKey = aaPublicKey.dump()
        self.sigAlgo     = sigAlgo
        self.dg1         = dg1
        self.validUntil  = validUntil
        self.loginCount  = loginCount
        self.isValid     = True

    def getSOD(self) -> ef.SOD:
        """Return SOD from object"""
        return ef.SOD.load(self.sod)

    def getAAPublicKey(self) -> AAPublicKey:
        return AAPublicKey.load(self.aaPublicKey)

    def getSigAlgo(self) -> Union[SignatureAlgorithm, None]:
        if self.sigAlgo is None:
            return None
        return SignatureAlgorithm.load(self.sigAlgo)

    def getDG1(self) -> Union[ef.DG1, None]:
        if self.dg1 is None:
            return None
        return ef.DG1.load(self.dg1)

    def setDG1(self, dg1: ef.DG1):
        assert isinstance(dg1, ef.DG1)
        self.dg1 = dg1.dump()

    def getIsValid(self) -> bool:
        """Return isValid from object"""
        return self.isValid


#def writeToDB_account(publicKey: AAPublicKey, sigAlgo: Union[SignatureAlgorithm, None], validUntil: datetime, sod: ef.SOD, connection: Connection) -> UserId:
#    """Write to database with ORM"""
#    try:
#        assert isinstance(publicKey, AAPublicKey)
#        assert isinstance(sigAlgo, (SignatureAlgorithm, type(None)))
#        assert isinstance(sod, ef.SOD)

#        if sigAlgo is not None:
#            sigAlog = b64encode(sigAlgo.dump())

#        uid  = UserId.fromAAPublicKey(publicKey)
#        accS = AccountStorage(
#            uid2str(uid),
#            b64encode(publicKey.dump()), 
#            sigAlog,
#            validUntil,
#            b64encode(sod)
#        )

#        logger.debug("Writing account object to database. uid={} valid_until={}".format(uid2str(uid), validUntil))
#        connection.getSession().add(accS)
#        connection.getSession().commit()
#        return uid

#    except Exception as e:
#        raise AccountStorageError("Problem with writing the object: " + str(e))

#def readFromDBwithUid_account(uid: UserId, connection: Connection) -> AccountStorage:
#    """Read from database with ORM"""
#    try:
#        logger.debug("Writing account object to database. uid={}", uid2str(uid))
#        result = connection.getSession() \
#            .query(AccountStorage) \
#            .filter(AccountStorage.uid == uid2str(uid)) \
#            .all()

#        if len(result) == 0:
#            logger.warning("Item not found in database or time limit exceeded")
#            raise AccountStorageError("Item not found in database or time limit exceeded.")

#        return result[0]
#    except Exception as e:
#        raise AccountStorageError("Problem with reading from object: " + str(e))

#def readFromDBwithPublicKey_account(publicKey: AAPublicKey, connection: Connection) -> AccountStorage:
#    """Read from database row with given public key"""
#    try:
#        return readFromDBwithUid_account(UserId.fromAAPublicKey(publicKey), connection)
#    except Exception as e:
#        raise AccountStorageError("Problem with reading from object: " + str(e))
