import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import List, Tuple, Union

from asn1crypto.x509 import Name

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
    ''' Abstract storage interface for user data and MRTD trustchain certificates (CSCA, DSC) '''
    
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

    @abstractmethod
    def getDSCbySerialNumber(self, issuer: Name, serialNumber: int) -> Union[x509.DocumentSignerCertificate, None]:
        """Get DSC"""
        pass

    @abstractmethod
    def getDSCbySubjectKey(self, subjectKey: bytes) -> Union[x509.DocumentSignerCertificate, None]:
        """Get DSC"""
        pass

    @abstractmethod
    def getCSCAbySubject(self, subject: Name) -> Union[x509.CscaCertificate, None]:
        pass

    @abstractmethod
    def getCSCAbySubjectKey(self, subjectKey: bytes) -> Union[x509.CscaCertificate, None]:
        """Get CSCA"""
        pass


class DatabaseAPIError(StorageAPIError):
    pass

class DatabaseAPI(StorageAPI):
    ''' 
    DatabaseAPI implements StorageAPI as persistent storage.
    It's defined as abstraction layer over class Connection (which uses PostgreSQL)
    to expose Connection interface to StorageAPI without mixing two interfaces.
    '''

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
        assert isinstance(account, AccountStorage)
        s = self._dbc.getSession()
        accnts = s.query(AccountStorage).filter(AccountStorage.uid == account.uid)
        if accnts.count() > 0:
            accnts[0].uid         = account.uid
            accnts[0].sod         = account.sod
            accnts[0].aaPublicKey = account.aaPublicKey
            accnts[0].sod         = account.sod
            accnts[0].dg1         = account.dg1
            accnts[0].session     = account.session
            accnts[0].validUntil  = account.validUntil
            accnts[0].loginCount  = account.loginCount
            accnts[0].isValid     = account.isValid
        else:
            s.add(account)
        s.commit()

    def getAccount(self, uid: UserId) -> AccountStorage:
        assert isinstance(uid, UserId)
        accounts = self._dbc.getSession().query(AccountStorage).filter(AccountStorage.uid == uid).all()
        if len(accounts) == 0:
            self._log.debug(":getAccountExpiry(): Account not found")
            raise SeEntryNotFound("Account not found.")
        assert isinstance(accounts[0], AccountStorage)
        return accounts[0]

    def deleteAccount(self, uid: UserId) -> None:
        assert isinstance(uid, UserId)
        self._dbc.getSession().query(AccountStorage).filter(AccountStorage.uid == uid).delete()
        self._dbc.getSession().commit()

    def getAccountExpiry(self, uid: UserId) -> datetime:
        assert isinstance(uid, UserId)
        items = self._dbc.getSession().query(AccountStorage).filter(AccountStorage.uid == uid).all()
        if len(items) == 0:
            self._log.debug(":getAccountExpiry(): Account not found")
            raise SeEntryNotFound("Account not found.")

        assert isinstance(items[0].getValidUntil(), datetime)
        return items[0].getValidUntil()

    def getDSCbySerialNumber(self, issuer: Name, serialNumber: int) -> Union[x509.DocumentSignerCertificate, None]:
        """ Get DSC by it's issuer and serial number. """
        assert isinstance(issuer, Name)
        assert isinstance(serialNumber, int)
        items = self._dbc.getSession() \
            .query(DocumentSignerCertificateStorage) \
            .filter(DocumentSignerCertificateStorage.issuer == issuer.human_friendly, \
                DocumentSignerCertificateStorage.serialNumber == str(serialNumber) \
            ).all()

        if len(items) == 0:
            return None
        return items[0].getObject()

    def getDSCbySubjectKey(self, subjectKey: bytes) -> Union[x509.DocumentSignerCertificate, None]:
        """ Get DSC by it's subject key. """
        assert isinstance(subjectKey, bytes)
        items = self._dbc.getSession() \
            .query(DocumentSignerCertificateStorage) \
            .filter(DocumentSignerCertificateStorage.subjectKey == subjectKey) \
            .all()

        if len(items) == 0:
            return None
        return items[0].getObject()

    def getCSCAbySubject(self, subject: Name) -> Union[x509.CscaCertificate, None]:
        """ Get CSCA by it's issuer and serial number. """
        assert isinstance(subject, Name)
        items = self._dbc.getSession() \
            .query(CSCAStorage) \
            .filter(CSCAStorage.subject == subject.human_friendly) \
            .all()

        if len(items) == 0:
            return None
        return items[0].getObject()

    def getCSCAbySubjectKey(self, subjectKey: bytes) -> Union[x509.CscaCertificate, None]:
        """ Get CSCA by it's subject key. """
        assert isinstance(subjectKey, bytes)
        items = self._dbc.getSession() \
            .query(CSCAStorage) \
            .filter(CSCAStorage.subjectKey == subjectKey) \
            .all()

        if len(items) == 0:
            return None
        return items[0].getObject()


class MemoryDBError(StorageAPIError):
    pass

class MemoryDB(StorageAPI):
    '''
    MemoryDB implements StorageAPI as non-peristent database.
    The data is stored in memory (RAM) and gets deleted as instance of MemoryDB is destroyed.
    The purpose of MemoryDB is testing of passID proto without needing to set up (or reset) proper database.
    Internally data is stored as dictionary in 4 categories: 
        proto_challenges -> Dictionary[CID, Tuple[Challenge, datetime]]
        accounts         -> Dictionary[UserId, AccountStorage]
        cscas            -> Set[CscaCertificate]
        dscs             -> Set[DocumentSignerCertificate]
    '''
    
    def __init__(self):
        self._d = {
            'proto_challenges' : {},
            'accounts' : {},
            'cscas' : set(),
            'dscs' : set(),
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
        assert isinstance(cid, CID)
        try:
            return self._d['proto_challenges'][cid]
        except Exception as e:
            raise SeEntryNotFound("Challenge not found") from e

    def addChallenge(self, challenge: Challenge, timedate: datetime) -> None:
        assert isinstance(challenge, Challenge)
        assert isinstance(timedate, datetime)
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

    def getDSCbySerialNumber(self, issuer: Name, serialNumber: int) -> Union[x509.DocumentSignerCertificate, None]:
        """Get DSC"""
        assert isinstance(issuer, Name)
        assert isinstance(serialNumber, int)
        for dsc in self._d['dscs']:
            if dsc.issuer == issuer and dsc.serial_number == serialNumber:
                return dsc
        return None

    def getDSCbySubjectKey(self, subjectKey: bytes) -> Union[x509.DocumentSignerCertificate, None]:
        """Get DSC"""
        assert isinstance(subjectKey, bytes)
        for dsc in self._d['dscs']:
            if dsc.subjectKey == subjectKey:
                return dsc
        return None

    def getCSCAbySubject(self, subject: Name)-> Union[x509.CscaCertificate, None]:
        """Get CSCA"""
        assert isinstance(subject, Name)
        for csca in self._d['cscas']:
            if csca.subject == subject:
                return csca
        return None

    def getCSCAbySubjectKey(self, subjectKey: bytes) -> Union[x509.CscaCertificate, None]:
        """Get CSCA"""
        assert isinstance(subjectKey, bytes)
        for csca in self._d['cscas']:
            if csca.subjectKey == subjectKey:
                return csca
        return None

    def addCscaCertificate(self, csca: x509.CscaCertificate):
        assert isinstance(csca, x509.CscaCertificate)
        self._d['cscas'].add(csca)

    def addDscCertificate(self, dsc: x509.DocumentSignerCertificate):
        assert isinstance(dsc, x509.DocumentSignerCertificate)
        self._d['dscs'].add(dsc)
