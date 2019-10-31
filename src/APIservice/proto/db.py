import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import List, Tuple, Union


from .challenge import CID, Challenge
from .user import UserId
from pymrtd import ef
from pymrtd.pki import x509
from pymrtd.pki.keys import AAPublicKey, SignatureAlgorithm



#sudo apt-get install postgresql postgresql-contrib
#pip install sqlalchemy
#pip install psycopg2 sqlalchemy
#sudo -u postgres createuser --interactive

from database.storage.storageManager import Connection

from database.storage.challengeStorage import * 
from database.storage.accountStorage import writeToDB_account, readFromDBwithUid_account, AccountStorageError


class StorageAPIError(Exception):
    pass

class StorageAPI(ABC):

    @abstractmethod
    def getChallenge(self, cid: CID) -> Tuple[Challenge, datetime]:
        """ 
        Function fetches challenge from db and returns
        challenge and time of creation.

        :param cid: Challenge id
        :return: Tuple[Challenge, datetime]
        :raises:
            DatabaseAPIError: If challenge is not found
        """

    # Proto challenge methods
    @abstractmethod
    def addChallenge(self, challenge: Challenge, timedate: datetime) -> None:
        """
        Add challenge to storage.
        :param challange:
        :param timdate: Date and time when challenge was created
        """
        pass

    @abstractmethod
    def deleteChallenge(self, cid: CID) -> None:
        pass

    # User methods
    @abstractmethod
    def accountExists(self, uid: UserId) -> bool:
        pass

    @abstractmethod
    def addOrUpdateAccount(self, aaPublicKey: AAPublicKey, sigAlgo: Union[SignatureAlgorithm, None], sod: ef.SOD, validUntil: datetime) -> UserId:
        pass

    @abstractmethod
    def deleteAccount(self, uid: UserId) -> None:
        pass

    @abstractmethod
    def getAccountExpiry(self, uid: UserId) -> datetime:
        """ Get account's credentials expiry """
        pass

    @abstractmethod
    def getAccountCredentials(self, uid: UserId) -> Tuple[AAPublicKey, Union[SignatureAlgorithm, None]]:
        """
        Returns user credentials needed to verify user's authentication via challenge.
        """
        pass

    # eMRTD PKI methods
    # TODO: implement



    
class DatabaseAPIError(StorageAPIError):
    pass

class DatabaseAPI(StorageAPI):

    def __init__(self, user: str, pwd: str, db: str):
        """Creating connection to the database and initialization of main strucutres"""
        self._dbc = Connection(user, pwd, db)

    def getChallenge(self, cid: CID) -> Tuple[Challenge, datetime]:
        """ 
        Function fetches challenge from db and returns
        challenge and time of creation.

        :param cid: Challenge id
        :return: Tuple[Challenge, datetime]
        :raises:
            DatabaseAPIError: If challenge is not found
        """

        result = self._dbc.getSession() \
           .query(ChallengeStorage) \
           .filter(ChallengeStorage.id == cid) \
           .all()
        
        if len(result) == 0:
            raise DatabaseAPIError("challenge not found")

        cs = result[0]
        c = cs.getChallenge()
        t = cs.createTime
        return (c, t)

    def addChallenge(self, challenge: Challenge, timedate: datetime) -> None:
        # TODO: check that challenge doesn't already exist
        cs = ChallengeStorage.fromChallenge(challenge, timedate)
        self._dbc.getSession().add(cs)
        self._dbc.getSession().commit()

    def deleteChallenge(self, cid: CID) -> None:
        # TODO: Implement
        #self._dbc.getSession().delete(cid)
        raise NotImplemented("DatabaseAPI.deleteChallenge not implemented")

    def accountExists(self, uid: UserId) -> bool:
        # TODO: Implement
        raise NotImplemented("DatabaseAPI.accountExists not implemented")

    def addOrUpdateAccount(self, aaPublicKey: AAPublicKey, sigAlgo: Union[SignatureAlgorithm, None], sod: ef.SOD, validUntil: datetime) -> UserId:
        # TODO: Implement
        raise NotImplemented("DatabaseAPI.addOrUpdateAccount not implemented")

    def deleteAccount(self, uid: UserId) -> None:
        # TODO: Implement
        raise NotImplemented("DatabaseAPI.deleteAccount not implemented")

    def getAccountExpiry(self, uid: UserId) -> datetime:
        # TODO: Implement
        raise NotImplemented("DatabaseAPI.getAccountExpiry not implemented")

    def getAccuountCredentials(self, uid: UserId) -> Tuple[AAPublicKey, Union[SignatureAlgorithm, None]]:
        """
        Returns user credentials needed to verify user's authentication via challenge.
        """
        # TODO: Implement
        raise NotImplemented("DatabaseAPI.getUserCredentials not implemented")


    #def getValidUntil(self, SOD):
    #    """Return datetime certificate is valid"""
    #    #TODO: get real data from SOD
    #    return datetime.now() - timedelta(days=15)

    #def register(self, challengeId: str, signature: str, publicKey: str, sodData: str) -> str:
    #    """API call: register"""
    #    #check signature
    #    APIcheckSignature_DB(challengeId, signature, config["registerTimeFrame"], self.conn)

    #    #save to database and return public key address
    #    validUntil = self.getValidUntil(sodData)
    #    return writeToDB_account(publicKey, sigAlgo, validUntil, sodData, self.conn)

    ##public key address(ripmd 160 over public key), challengeId, signature
    #def login(self, challengeId: str, signature: str, uid: UserId) -> dict:
    #    """API call: login"""
    #    #check signature
    #    APIcheckSignature_DB(challengeId, signature, config["registerTimeFrame"], self.conn)
    #    #read from database
    #    return readFromDBwithUid_account(publicKeyAddress, self.conn)


class MemoryDBError(StorageAPIError):
    pass

class MemoryDB(StorageAPI):
    def __init__(self):
        self._d = {
            'proto_challenges' : {},
            'accounts' : {},
            'certificates' : {}
        }

    def getChallenge(self, cid: CID) -> Tuple[Challenge, datetime]:
        """ 
        Function fetches challenge from db and returns
        challenge and time of creation.

        :param cid: Challenge id
        :return: Tuple[Challenge, datetime]
        :raises:
            MemoryDBError: If challenge is not found
        """
        try:
            return self._d['proto_challenges'][cid]
        except Exception as e:
            raise MemoryDBError("Challenge not found") from e

    def addChallenge(self, challenge: Challenge, timedate: datetime) -> None:
        if challenge.id in self._d['proto_challenges']:
            raise MemoryDBError("Challenge already exists")
        self._d['proto_challenges'][challenge.id] = (challenge, timedate)

    def deleteChallenge(self, cid: CID) -> None:
        assert isinstance(cid, CID)
        if cid in self._d['proto_challenges']:
            del self._d['proto_challenges'][cid]

    def accountExists(self, uid: UserId) -> bool:
        assert isinstance(uid, UserId)
        return uid in self._d['accounts']

    def addOrUpdateAccount(self, aaPublicKey: AAPublicKey, sigAlgo: Union[SignatureAlgorithm, None], sod: ef.SOD, validUntil: datetime) -> UserId:
        assert isinstance(aaPublicKey, AAPublicKey)
        assert isinstance(sigAlgo, (SignatureAlgorithm, type(None)))
        assert isinstance(sod, ef.SOD)
        assert isinstance(validUntil, datetime)

        uid = UserId.fromAAPublicKey(aaPublicKey)
        self._d['accounts'][uid] = (aaPublicKey, sigAlgo, sod, validUntil)
        return uid

    def deleteAccount(self, uid: UserId) -> None:
        assert isinstance(uid, UserId)
        if uid in self._d['accounts']:
            del self._d['accounts'][uid]

    def getAccountExpiry(self, uid: UserId) -> datetime:
        assert isinstance(uid, UserId)
        if uid not in self._d['accounts']:
            raise MemoryDBError("Account not found")
        accnt = self._d['accounts'][uid]
        return accnt[3]

    def getAccountCredentials(self, uid: UserId) -> Tuple[AAPublicKey, Union[SignatureAlgorithm, None], datetime]:
        """
        Returns user credentials needed to verify user's authentication via challenge.
        """
        assert isinstance(uid, UserId)
        if uid not in self._d['accounts']:
            raise MemoryDBError("Account not found")
        accnt = self._d['accounts'][uid]
        return (accnt[0], accnt[1], accnt[3])