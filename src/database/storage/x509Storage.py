from pymrtd.pki.x509 import CscaCertificate, DocumentSignerCertificate
from settings import logger

class CSCAStorageError(Exception):
    pass

class DocumentSignerCertificateStorageError(Exception):
    pass

class CSCAStorage(object):
    """Class for interaction between code structure and database - CSCA"""

    def __init__(self, dsc: CscaCertificate):
        """Initialization class with serialization of DSC"""
        self.serializeCSCA()
        self.issuerCountry = dsc.issuerCountry
        self.fingerprint = dsc.fingerprint
        self.subjectKey = dsc.subjectKey
        self.authorityKey = dsc.authorityKey
        self.thisUpdate = dsc['tbs_certificate']['validity']['not_before'].native
        self.nextUpdate = dsc['tbs_certificate']['validity']['not_after'].native

    def serializeCSCA(self, csca: CscaCertificate):
        """Function serialize CSCA object to sequence"""
        self.object = csca.dump()

    def getObject(self) -> CscaCertificate:
        """Returns CSCA object"""
        return DocumentSignerCertificate.load(self.object)

from database.storage.storageManager import Connection

def writeToDB_DSC(csca: CscaCertificate, connection: Connection):
    """Write to database with ORM"""
    try:
        logger.info("Writing CSCA object to database. Country: " + csca.issuerCountry)
        connection.getSession().add(CSCAStorage(csca))
        connection.getSession().commit()

    except Exception:
        raise CSCAStorageError("Problem with writing the object")

def readFromDB_DSC(issuerCountry: str, connection: Connection) -> CscaCertificate:
    """Reading from database"""
    try:
        logger.info("Reading CSCA object from database. Country:" + issuerCountry)
        connection.getSession().query(CSCAStorage).count()
        ter = connection.getSession().query(CSCAStorage).all()[connection.getSession().query(CSCAStorage).count()-1]
        ter1 = ter.getObject()

    except Exception:
        raise CSCAStorageError("Problem with writing the object")


class DocumentSignerCertificateStorage(object):
    """Class for interaction between code structure and database - DSC"""

    def __init__(self, dsc: DocumentSignerCertificate, issuerCountry: str):
        """Initialization class with serialization of DSC"""
        self.serializeDSC(dsc)
        self.issuerCountry = issuerCountry
        self.fingerprint = dsc.fingerprint
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
        connection.getSession().add(DocumentSignerCertificateStorage(dsc, issuerCountry))
        connection.getSession().commit()

    except Exception:
        raise DocumentSignerCertificateStorageError("Problem with writing the object")

def readFromDB_DSC(issuerCountry: str, connection: Connection) -> DocumentSignerCertificate:
    """Reading from database"""
    try:
        logger.info("Reading CRL object from database. Country:" + issuerCountry)
        connection.getSession().query(DocumentSignerCertificateStorage).count()
        ter = connection.getSession().query(DocumentSignerCertificateStorage).all()[connection.getSession().query(DocumentSignerCertificateStorage).count()-1]
        ter1 = ter.getObject()

    except Exception:
        raise DocumentSignerCertificateStorageError("Problem with writing the object")
