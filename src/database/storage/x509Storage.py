'''
    File name: x509Storage.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from pymrtd.pki.x509 import CscaCertificate, DocumentSignerCertificate
import logging

logger = logging.getLogger(__name__)

class CSCAStorageError(Exception):
    pass

class DocumentSignerCertificateStorageError(Exception):
    pass

class CSCAStorage(object):
    """Class for interaction between code structure and database - CSCA"""

    def __init__(self, csca: CscaCertificate):
        """Initialization class with serialization of DSC"""
        self.serializeCSCA(csca)
        self.issuer = csca.issuer.human_friendly
        try:
            self.serialNumber = str(csca.serial_number)
        except Exception as e:
            self.serialNumber = ""
        self.fingerprint = csca.fingerprint
        self.subject = csca.subject.human_friendly
        self.subjectKey = csca.subjectKey
        self.authorityKey = csca.authorityKey
        self.thisUpdate = csca['tbs_certificate']['validity']['not_before'].native
        self.nextUpdate = csca['tbs_certificate']['validity']['not_after'].native

    def serializeCSCA(self, csca: CscaCertificate):
        """Function serialize CSCA object to sequence"""
        self.object = csca.dump()

    def getObject(self) -> CscaCertificate:
        """Returns CSCA object"""
        return DocumentSignerCertificate.load(self.object)

from database.storage.storageManager import Connection

def writeToDB_CSCA(csca: CscaCertificate, connection: Connection):
    """Write to database with ORM"""
    try:
        logger.info("Writing CSCA object to database. Country: " + csca.issuerCountry)
        connection.getSession().add(CSCAStorage(csca))
        connection.getSession().commit()

    except Exception:
        raise CSCAStorageError("Problem with writing the object")

def readFromDB_CSCA_issuer_serialNumber(issuer: str, serialNumber: int, connection: Connection) -> []:
    """Reading from database"""
    try:
        logger.info("Reading CSCA object from database. Issuer:" + issuer + ", serial number: " + str(serialNumber))
        return connection.getSession().query(CSCAStorage).filter(CSCAStorage.issuer == issuer,
                                                                 CSCAStorage.serialNumber == str(serialNumber.native)).all()
    except Exception as e:
        raise CSCAStorageError("Problem with writing the object" + e)

def readFromDB_CSCA_authorityKey(authorityKey: bytes, connection: Connection) -> []:
    """Reading from database"""
    try:
        logger.info("Reading CSCA object from database by authority key")
        return connection.getSession().query(CSCAStorage).filter(CSCAStorage.authorityKey == authorityKey).all()
    except Exception as e:
        raise CSCAStorageError("Problem with writing the object" + e)

def deleteFromDB_CSCA(CSCAs: [],connection: Connection):
    """Reading from database"""
    try:
        logger.info("Delete DSCs; size:" + str(len(CSCAs)))
        if len(CSCAs) == 0:
            logger.debug("Empty array. Nothing to delete.")
        for item in CSCAs:
            try:
                connection.getSession().delete(item)
            except Exception as e:
                logger.error("Action delete failed. No item in database or object was not CSCA.")
        connection.getSession().commit()
    except Exception as e:
        raise DocumentSignerCertificateStorageError("Problem with writing the object" + e)

class DocumentSignerCertificateStorage(object):
    """Class for interaction between code structure and database - DSC"""

    def __init__(self, dsc: DocumentSignerCertificate, issuerCountry: str):
        """Initialization class with serialization of DSC"""
        self.serializeDSC(dsc)
        self.issuer = dsc.issuer.human_friendly
        try:
            self.serialNumber = str(dsc.serial_number)
        except Exception as e:
            self.serialNumber = ""
        self.fingerprint = dsc.fingerprint
        self.subject = dsc.subject.human_friendly
        self.subjectKey = dsc.subjectKey
        self.authorityKey = dsc.authorityKey
        self.thisUpdate = dsc['tbs_certificate']['validity']['not_before'].native
        self.nextUpdate = dsc['tbs_certificate']['validity']['not_after'].native

    def serializeDSC(self, dsc: DocumentSignerCertificate):
        """Function serialize DSC object to sequence"""
        self.object = dsc.dump()

    def getObject(self) -> DocumentSignerCertificate:
        """Returns DSC object"""
        return DocumentSignerCertificate.load(self.object)


def writeToDB_DSC(dsc: DocumentSignerCertificate, issuerCountry: str, connection: Connection):
    """Write to database with ORM"""
    try:
        logger.info("Writing DSC object to database. Country: " + issuerCountry)
        a = DocumentSignerCertificateStorage(dsc, issuerCountry)
        connection.getSession().add(a)
        connection.getSession().commit()

    except Exception as e:
        raise DocumentSignerCertificateStorageError("Problem with writing the object: " + e)

def readFromDB_DSC_issuer_serialNumber(issuer: str, serialNumber: int, connection: Connection) -> DocumentSignerCertificate:
    """Reading from database"""
    try:
        logger.info("Reading DSC object from database. Issuer:" + issuer + ", serial number: " + str(serialNumber))
        return connection.getSession().query(DocumentSignerCertificateStorage).filter(DocumentSignerCertificateStorage.issuer == issuer,
                                                                                      DocumentSignerCertificateStorage.serialNumber == str(serialNumber.native)).all()
    except Exception as e:
        raise DocumentSignerCertificateStorageError("Problem with writing the object" + e)

def readFromDB_DSC_issuer(issuer: str, connection: Connection) -> DocumentSignerCertificate:
    """Reading from database"""
    try:
        logger.info("Reading DSC object from database. Issuer:" + issuer)
        return connection.getSession().query(DocumentSignerCertificateStorage).filter(DocumentSignerCertificateStorage.issuer == issuer).all()
    except Exception:
        raise DocumentSignerCertificateStorageError("Problem with writing the object")

def readFromDB_DSC_authorityKey(authorityKey: bytes, connection: Connection) -> DocumentSignerCertificate:
    """Reading from database"""
    try:
        logger.info("Reading DSC object from database with authority key.")
        return connection.getSession().query(DocumentSignerCertificateStorage).filter(DocumentSignerCertificateStorage.authorityKey == authorityKey).all()
    except Exception:
        raise DocumentSignerCertificateStorageError("Problem with writing the object")

def deleteFromDB_DSC(DSCs: [],connection: Connection):
    """Reading from database"""
    try:
        logger.info("Delete DSCs; size:" + str(len(DSCs)))
        if len(DSCs) == 0:
            logger.debug("Empty array. Nothing to delete.")

        for item in DSCs:
            try:
                connection.getSession().delete(item)
            except Exception as e:
                logger.error("Action delete failed. No item in database or object was not DSC.")
        connection.getSession().commit()
    except Exception as e:
        raise DocumentSignerCertificateStorageError("Problem with writing the object" + e)
