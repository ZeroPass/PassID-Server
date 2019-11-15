import logging
from pymrtd.pki.crl import CertificateRevocationList
from settings import *

logger = logging.getLogger(__name__)


class CertificateRevocationListStorageError(Exception):
    pass

class CertificateRevocationListStorage(object):
    """Class for interaaction between code structure and database"""
    _object = None
    _issuerCountry = None
    _size = None
    _thisUpdate = None
    _nextUpdate = None
    _signatureAlgorithm = None
    _signatureHashAlgorithm = None
    _fingerprint = None

    def __init__(self, crl: CertificateRevocationList, issuerCountry: str):
        """Initialization class with serialization of CRL"""
        self.size = crl.size
        self.issuerCountry = issuerCountry
        self.thisUpdate = crl.thisUpdate
        self.nextUpdate = crl.nextUpdate
        self.signatureAlgorithm = crl.signatureAlgorithm
        self.signatureHashAlgorithm = crl.signatureHashAlgorithm
        self.serializeCRL(crl)

    def serializeCRL(self, crl: CertificateRevocationList):
        """Function serialize CRL object to sequence"""
        self.object = crl.dump()

    def getObject(self) -> CertificateRevocationList:
        """Returns crl object"""
        return CertificateRevocationList.load(self.object)

#
#Storage management functions
#
from database.storage.storageManager import Connection

def writeToDB_CRL(crl: CertificateRevocationList, issuerCountry: str, connection: Connection):
    """Write to database with ORM"""
    try:
        logger.info("Writing CRL object to database. Country: " + crl.issuerCountry)
        crls = CertificateRevocationListStorage(crl, issuerCountry)
        connection.getSession().add(crls)
        connection.getSession().commit()

    except Exception as e:
        raise CertificateRevocationListStorageError("Problem with writing the object: " + str(e))

def readFromDB_CRL(connection: Connection) -> []:
    """Reading from database"""
    try:
        logger.info("Reading CRL objects from database.")
        if connection.getSession().query(CertificateRevocationListStorage).count() > 0:
            return connection.getSession().query(CertificateRevocationListStorage).all()
        raise CertificateRevocationListStorageError("There is no CRL in database.")

    except Exception as e:
        raise CertificateRevocationListStorageError("Problem with reading the object: " + str(e))
