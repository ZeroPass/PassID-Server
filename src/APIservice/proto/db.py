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
from database.storage.accountStorage import AccountStorage, AccountStorageError
from database.storage.x509Storage import DocumentSignerCertificateStorage, CSCAStorage

class StorageAPIError(Exception):
    pass

class SeEntryNotFound(StorageAPIError):
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
    def addOrUpdateAccount(self, account: AccountStorage) -> None:
        pass

    @abstractmethod
    def deleteAccount(self, uid: UserId) -> None:
        pass

    @abstractmethod
    def getAccount(self, uid: UserId) -> AccountStorage:
        """ Get account """
        pass

    @abstractmethod
    def getAccountExpiry(self, uid: UserId) -> datetime:
        """ Get account's credentials expiry """
        pass

    #@abstractmethod
    #def getAccountCredentials(self, uid: UserId) -> Tuple[AAPublicKey, Union[SignatureAlgorithm, None]]:
    #    """
    #    Returns user credentials needed to verify user's authentication via challenge.
    #    """
    #    pass

    @abstractmethod
    def getDSCbySerialNumber(self, issuer: str, serialNumber: str):
        """Get DSC"""
        pass

    @abstractmethod
    def getDSCbySubjectKey(self, subjectKey: bytes):
        """Get DSC"""
        pass

    @abstractmethod
    def getCSCAbySerialNumber(self, issuer: str, serialNumber: str):
        pass

    @abstractmethod
    def getCSCAbySubjectKey(self, subjectKey: bytes):
        """Get CSCA"""
        pass


class DatabaseAPIError(StorageAPIError):
    pass

class DatabaseAPI(StorageAPI):

    def __init__(self, user: str, pwd: str, db: str):
        """Creating connection to the database and initialization of main strucutres"""
        self._log = logging.getLogger(DatabaseAPI.__name__)
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
        assert isinstance(cid, CID)

        result = self._dbc.getSession() \
           .query(ChallengeStorage) \
           .filter(ChallengeStorage.id == str(cid)) \
           .all()
        
        if len(result) == 0:
            raise SeEntryNotFound("challenge not found")

        cs = result[0]
        c = cs.getChallenge()
        t = cs.createTime
        return (c, t)

    def addChallenge(self, challenge: Challenge, timedate: datetime) -> None:
        assert isinstance(challenge, Challenge)
        assert isinstance(timedate, datetime)
        cs = ChallengeStorage.fromChallenge(challenge, timedate)

        if self._dbc.getSession().query(ChallengeStorage).filter(ChallengeStorage.id == str(challenge.id)).count() > 0:
            raise DatabaseAPIError("Challenge already exists")

        self._dbc.getSession().add(cs)
        self._dbc.getSession().commit()

    def deleteChallenge(self, cid: CID) -> None:
        assert isinstance(cid, CID)
        self._dbc.getSession().query(ChallengeStorage).filter(ChallengeStorage.id == str(cid)).delete()
        self._dbc.getSession().commit()

    def accountExists(self, uid: UserId) -> bool:
        assert isinstance(uid, UserId)
        return True if self._dbc.getSession().query(AccountStorage).filter(AccountStorage.uid == uid).count() > 0 else False

    def addOrUpdateAccount(self, account: AccountStorage) -> None:
        s = self._dbc.getSession()
        accnts = s.query(AccountStorage).filter(AccountStorage.uid == account.uid)
        if accnts.count() > 0:
            accnts[0].setDG1(account.getDG1())
            r = 9
        else:
            s.add(account)
        s.commit()

    def getAccount(self, uid: UserId) -> AccountStorage:
        accounts = self._dbc.getSession().query(AccountStorage).filter(AccountStorage.uid == uid).all()
        if len(accounts) == 0:
            self._log.ddebug(":getAccountExpiry(): Account not found")
            raise SeEntryNotFound("Account not found.")
        assert isinstance(accounts[0], AccountStorage)
        return accounts[0]

    #def addOrUpdateAccount(self, aaPublicKey: AAPublicKey, sigAlgo: Union[SignatureAlgorithm, None], sod: ef.SOD, validUntil: datetime) -> UserId:
    #    #    def __init__(self, uid: str, aaPublicKey: str, sigAlgo: Union[str, None], validUntil: datetime, sod: str):

    #    sigAlgoDump = None
    #    if sigAlgo is not None:
    #        sigAlgoDump = sigAlgo.dump()

    #    uid = UserId.fromAAPublicKey(aaPublicKey)
    #    accS = AccountStorage(str(uid), aaPublicKey.dump(), sigAlgoDump, validUntil, sod.dump())

    #    self._dbc.getSession().add(accS)
    #    self._dbc.getSession().commit()
    #    return uid

    def deleteAccount(self, uid: UserId) -> None:
        assert isinstance(uid, UserId)
        self._dbc.getSession().query(AccountStorage).filter(AccountStorage.uid == uid).delete()
        self._dbc.getSession().commit()

    def getAccountExpiry(self, uid: UserId) -> datetime:
        assert isinstance(uid, UserId)
        items = self._dbc.getSession().query(AccountStorage).filter(AccountStorage.uid == uid).all()
        if len(items) == 0:
            self._log.ddebug(":getAccountExpiry(): Account not found")
            raise SeEntryNotFound("Account not found.")

        assert isinstance(items[0].getValidUntil(), datetime)
        return items[0].getValidUntil()

    #def getAccountCredentials(self, uid: UserId) -> Tuple[AAPublicKey, Union[SignatureAlgorithm, None]]:
    #    """
    #    Returns user credentials needed to verify user's authentication via challenge.
    #    """
    #    assert isinstance(uid, UserId)
    #    items = self._dbc.getSession().query(AccountStorage).filter(AccountStorage.uid == uid).all()
    #    if len(items) == 0:
    #        self._log.ddebug(":getAccountCredentials(): Account not found")
    #        raise SeEntryNotFound("Account not found.")
    #    return (items[0].getAAPublicKey(), items[0].getSigAlgo(), items[0].getValidUntil())

    #1.) issuer + serijska stevilka
    #2.) subjeect key identifier

    def getDSCbySerialNumber(self, issuer: str, serialNumber: str):
        """Get DSC"""
        items = self._dbc.getSession().query(DocumentSignerCertificateStorage).filter(DocumentSignerCertificateStorage.issuer == issuer,
                                                                                      DocumentSignerCertificateStorage.serialNumber == serialNumber).all()
        return items

    def getDSCbySubjectKey(self, subjectKey: bytes):
        """Get DSC"""
        items = self._dbc.getSession().query(DocumentSignerCertificateStorage).filter(DocumentSignerCertificateStorage.subjectKey == subjectKey).all()
        return items

    def getCSCAbySerialNumber(self, issuer: str, serialNumber: str):
        """Get CSCA certificate"""
        items = self._dbc.getSession().query(CSCAStorage).filter(CSCAStorage.issuer == issuer,
                                                                 CSCAStorage.serialNumber == serialNumber).all()
        return items

    def getCSCAbySubjectKey(self, subjectKey: bytes):
        """Get DSC"""
        items = self._dbc.getSession().query(CSCAStorage).filter(CSCAStorage.subjectKey == subjectKey).all()
        return items


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
            'cscas' : {},
            'dscs' : {},
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
            raise SeEntryNotFound("Challenge not found") from e

    def addChallenge(self, challenge: Challenge, timedate: datetime) -> None:
        if challenge.id in self._d['proto_challenges']:
            raise MemoryDBError("Challenge already exists")
        self._d['proto_challenges'][challenge.id] = (challenge, timedate)

    def deleteChallenge(self, cid: CID) -> None:
        if cid in self._d['proto_challenges']:
            del self._d['proto_challenges'][cid]

    def accountExists(self, uid: UserId) -> bool:
        assert isinstance(uid, UserId)
        return uid in self._d['accounts']

    def addOrUpdateAccount(self, account: AccountStorage) -> None:
        assert isinstance(account, AccountStorage)
        self._d['accounts'][account.uid] = account

    def getAccount(self, uid: UserId) -> AccountStorage:
        assert isinstance(uid, UserId)
        if uid not in self._d['accounts']:
            raise SeEntryNotFound("Account not found")
        return self._d['accounts'][uid]

    def deleteAccount(self, uid: UserId) -> None:
        assert isinstance(uid, UserId)
        if uid in self._d['accounts']:
            del self._d['accounts'][uid]

    def getAccountExpiry(self, uid: UserId) -> datetime:
        assert isinstance(uid, UserId)
        if uid not in self._d['accounts']:
            raise SeEntryNotFound("Account not found")
        a = self.getAccount(uid)
        return a.validUntil

    #def getAccountCredentials(self, uid: UserId) -> Tuple[AAPublicKey, Union[SignatureAlgorithm, None], datetime]:
    #    """
    #    Returns user credentials needed to verify user's authentication via challenge.
    #    """
    #    assert isinstance(uid, UserId)
    #    if uid not in self._d['accounts']:
    #        raise SeEntryNotFound("Account not found")
    #    a = self.getAccount(uid)
    #    return (a.getAAPublicKey(), a.getSigAlgo(), a.validUntil)


    def getDSCbySerialNumber(self, issuer: str, serialNumber: str):
        """Get DSC"""
        for dsc in self._d['dscs']:
            if dsc.issuer.native == issuer and dsc.serialNumber == serialNumber:
                return dsc
        return None

    def getDSCbySubjectKey(self, subjectKey: bytes):
        """Get DSC"""
        for dsc in self._d['dscs']:
            if dsc.subjectKey == subjectKey:
                return dsc
        return None

    def getCSCAbySerialNumber(self, issuer: str, serialNumber: str):
        """Get CSCA"""
        for csca in self._d['cscas']:
            if csca.issuer.native == issuer and csca.serialNumber == serialNumber:
                return csca
        return None

    def getCSCAbySubjectKey(self, subjectKey: bytes):
        """Get CSCA"""
        for csca in self._d['cscas']:
            if csca.subjectKey == subjectKey:
                return dsc
        return None

    def updateAccountDG1(self, uid: UserId, dg1: ef.DG1):
        if uid not in self._d['accounts']:
            raise SeEntryNotFound("Account not found")
        accnt = self._d['accounts'][uid]
        accnt = list(accnt)
        accnt[4] = dg1
        self._d['accounts'][uid] = tuple(accnt)
