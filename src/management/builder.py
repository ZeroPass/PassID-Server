'''
    File name: builder.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from ldif3 import LDIFParser
from asn1crypto import crl, x509
import re
import logging

from pymrtd.pki.crl import CertificateRevocationList
from pymrtd.pki.x509 import DocumentSignerCertificate, Certificate, CscaCertificate, MasterListSignerCertificate

from database.storage.certificateRevocationListStorage import CertificateRevocationListStorageError, writeToDB_CRL, readFromDB_CRL
from database.storage.x509Storage import writeToDB_CSCA, writeToDB_DSC

from management.filter import Filter

from typing import Dict
from datetime import datetime


#from pymrtd import ef
from pymrtd.pki.ml import CscaMasterList
from database.storage.storageManager import Connection, truncateAll

from settings import *

logger = logging.getLogger(__name__)

#subject - authority
#issucer - subject


def get_issuer_cert(issued_cert: Certificate, root_certs: Dict[bytes, Certificate]):
    if issued_cert.self_signed == 'maybe':
        return issued_cert
    if issued_cert.authority_key_identifier is not None:
        if issued_cert.authority_key_identifier in root_certs:
            return root_certs[issued_cert.authority_key_identifier]
    else:
        issuer = issued_cert.issuer
        for skid, rc in root_certs.items():
            if rc.subject == issuer:
                return rc

    return None

class BuilderError(Exception):
    pass

class Builder:
    """Building database structures and connections between certificates"""

    def __init__(self, cscaFile, dscCrlFile, config):
        """CSCAfile and dscCrlFIle need to be in ldif format - downloaded from ICAO website"""

        conn = Connection(config.database.user, config.database.pwd, config.database.db)
        self.clearDatabase(conn)
        self.parseDscCrlFile(dscCrlFile, conn)
        self.parseCSCAFile(cscaFile, conn)
        self.processCRL(conn)
        self._log = logging.getLogger(Builder.__name__)

    def clearDatabase(self, connection: Connection):
        """Clear database"""
        truncateAll(connection)

    def parseDscCrlFile(self, dscCrlFile, connection: Connection):
        """Parsing DSC/CRL file"""
        parser = LDIFParser(dscCrlFile)
        for dn, entry in parser.parse():
            if 'userCertificate;binary' in entry:
                countryCode = re.findall(r'[c,C]{1}=(.*)(,dc=data){1}', dn)[0][0]
                dsc = x509.Certificate.load(*entry['userCertificate;binary'])
                #parse to our object
                dsc.__class__ = DocumentSignerCertificate
                dsc.__init__()
                #write to DB
                writeToDB_DSC(dsc, countryCode, connection)

            if 'certificateRevocationList;binary' in entry:
                countryCode = re.findall(r'[c,C]{1}=(.*)(,dc=data){1}', dn)[0][0]
                revocationList = crl.CertificateList.load(*entry['certificateRevocationList;binary'])
                #parse to our object
                revocationList.__class__ = CertificateRevocationList
                revocationList.__init__()
                #write to DB
                writeToDB_CRL(revocationList, countryCode, connection)


    def verifyCSCAandWrite(self, csca: CscaCertificate, issuingCert: CscaCertificate, connection: Connection):
        try:
            #is CSCA still valid?
            if not csca.isValidOn(datetime.utcnow()):
                raise Exception()

            #is signature of CSCA correct?
            csca.verify(issuingCert)

            #write to database
            writeToDB_CSCA(csca, connection)

        except Exception as e:
            self._log.error("Certificate is not valid anymore or verification failed.")
    def parseCSCAFile(self, CSCAFile, connection: Connection):
        """Parsing CSCA file"""
        parser = LDIFParser(CSCAFile)
        for dn, entry in parser.parse():
            if 'CscaMasterListData' in entry:
                ml = CscaMasterList()
                masterList = ml.load(*entry['CscaMasterListData'])
                try:
                    # verify masterlist - if failed it returns exception
                    masterList.verify()
                except Exception as e:
                    self._log.error("Integrity verification failed for master list issued by {}."
                                  .format(masterList.signerCertificates[0].subject.native['country_name']))

                cscas = {}
                skipped_cscas = []
                for csca in masterList.cscaList:
                    if csca.key_identifier not in cscas:
                        cscas[csca.key_identifier] = csca

                    if csca.self_signed != 'maybe':
                        if csca.authority_key_identifier not in cscas:
                            skipped_cscas.append(csca)
                            continue
                        issuing_cert = cscas[csca.authority_key_identifier]
                    else:
                        issuing_cert = csca

                    self.verifyCSCAandWrite(csca, issuing_cert, connection)

                for csca in skipped_cscas:
                    issuer_cert = get_issuer_cert(csca, cscas)
                    if issuer_cert is None:
                        self._log.error("Could not verify signature of CSCA C={} SerNo={}. Issuing CSCA not found! The CSCA is skipped and not stored in database."
                                      .format(csca.subject.native['country_name'], hex(csca.serial_number).rstrip("L").lstrip("0x")))
                    else:
                        self.verifyCSCAandWrite(csca, issuer_cert, connection)

                    # verify master list signer certificates
                for mlsig_cert in masterList.signerCertificates:
                    issuer_cert = get_issuer_cert(mlsig_cert, cscas)
                    if issuer_cert is None:
                        self._log.info(
                            "Could not verify signature of master list signer certificate. Issuing CSCA not found! [C={} Ml-Sig-SerNo={}]".format(
                                mlsig_cert.subject.native['country_name'], hex(mlsig_cert.serial_number).rstrip("L").lstrip("0x")))
                    else:
                        try:
                            mlsig_cert.verify(issuer_cert)
                        except Exception as e:
                            self._log.info(
                                "Failed to verify master list signer C={} Ml-Sig-SerNo={}\n\treason: {}".format(
                                    mlsig_cert.subject.native['country_name'], hex(mlsig_cert.serial_number).rstrip("L").lstrip("0x"), str(e)))


    #gledam subject key, ce ga ni gledam issucer in serial key
    def iterateCRL(self, crl: CertificateRevocationListStorageError, connection: Connection):
        try:
            #f = open("test.crl", "wb")
            #r = crl.dump()
            #f.write(r)
            #f.close()
            #for key in crl['tbs_cert_list']['revoked_certificates']:
            Filter(crl, connection)
        except Exception as e:
            raise BuilderError("Error in iterateCRL function: " + e)


    def processCRL(self, connection: Connection):
        """Iterate through CRL and delete revocated certificates"""
        try:
            crlArray = readFromDB_CRL(connection)
            for crl in crlArray:
                self.iterateCRL(crl.getObject(), connection)

        except CertificateRevocationListStorageError as e:
            logger.error("Exception description:" + e)
        except Exception as e:
            raise Exception("Unknown error.")
