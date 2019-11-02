'''
    File name: filter.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from asn1crypto import crl, x509
import re

from settings import *
from database.storage.x509Storage import readFromDB_DSC_issuer_serialNumber, \
                                        readFromDB_CSCA_issuer_serialNumber, \
                                        readFromDB_CSCA_authorityKey, \
                                        readFromDB_DSC_authorityKey, \
                                        readFromDB_DSC_issuer, \
                                        deleteFromDB_DSC, \
                                        deleteFromDB_CSCA

from pymrtd.pki.crl import CertificateRevocationList

class FilterError(Exception):
    pass

class Filter:
    """Filtration of CSCA, eCSCA and DSCs"""

    from database.storage.storageManager import Connection
    def __init__(self, crl: CertificateRevocationList, connection: Connection):
        """Start the process"""
        try:
            issuer = self.getIssuer(crl)
            for item in crl['tbs_cert_list']['revoked_certificates']:
                self.deleteCertificateByIssuerAndSerialNumber(issuer, item["user_certificate"], connection)
        except Exception as e:
            raise FilterError("Error in iterateCRL function: " + e)


    def getIssuer(self, crl: CertificateRevocationList):
        """Get human readable issuer"""
        return crl.issuer.human_friendly

    def findConnectedCertificatesUnderCSCA(self, CSCA, connection: Connection):
        """Find connected certificates by both modes"""
        DSCsMode1 = self.checkByIssuerDSC(CSCA.subject, connection)
        DSCsMode2 = self.checkBySubjectKeyDSC(CSCA.subjectKey, connection)
        return DSCsMode1 + DSCsMode2

    def findConnectedCertificatesCSCAtoLCSCA(self, CSCA, connection: Connection):
        """Find connected certificates: if two CSCA have the same subjectKey"""
        return readFromDB_CSCA_authorityKey(CSCA.subjectKey, connection)

    def checkByIssuerDSC(self, issuer: str, connection: Connection) -> []:
        """Check connection between certificates by first mode (issuer and serial number)"""
        return readFromDB_DSC_issuer(issuer, connection)

    def checkBySubjectKeyDSC(self, subjectKey: bytes, connection: Connection) -> []:
        """Check connection between certificate by second mode (CSCA subject key t0 DSC authority key) //subject key is actualy authority key in the DSC"""
        return readFromDB_DSC_authorityKey(subjectKey, connection)


    def deleteCertificateByIssuerAndSerialNumber(self, issuer, serialNumber, connection: Connection) -> []:
        """Find in database certificates with selected issuer and serial number"""
        logger.debug("Find linked certificates with issuer: " + issuer + " and serial number:" + str(serialNumber))

        dataDSC = readFromDB_DSC_issuer_serialNumber(issuer, serialNumber, connection)
        dataCSCA = readFromDB_CSCA_issuer_serialNumber(issuer, serialNumber, connection)
        #dataCSCA = readFromDB_CSCA_last("", connection)

        lengthDSC = len(dataDSC)
        lengthCSCA = len(dataCSCA)
        if lengthDSC and lengthCSCA == 0:
            logger.debug("Linked certificate not found.")
            return

        if lengthDSC > 0:
            deleteFromDB_DSC(dataDSC, connection)

        foundItemsLCSCA = []
        if lengthCSCA > 0:
            """Add other CSCAs that are connected to first one"""
            foundItemsLCSCA = self.findConnectedCertificatesCSCAtoLCSCA(dataCSCA[0], connection)
            #merge first CSCA with connected ones
            foundItemsLCSCA.append(dataCSCA[0])

        for item in foundItemsLCSCA:
            #delete from database all CSCAs and belonging DSCAs to it
            foundItemsDSC = self.findConnectedCertificatesUnderCSCA(item, connection)

            if len(foundItemsDSC) > 0:
                """Delete DSCs"""
                deleteFromDB_DSC(foundItemsDSC, connection)

            #delete CSCA
            deleteFromDB_CSCA([item], connection)

