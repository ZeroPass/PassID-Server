'''
    File name: builder.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from ldif3 import LDIFParser
from asn1crypto import crl, x509
import re

from pymrtd.pki.crl import CertificateRevocationList
from pymrtd.pki.x509 import DocumentSignerCertificate, Certificate, CscaCertificate, MasterListSignerCertificate

from database.storage.certificateRevocationListStorage import writeToDB_CRL, readFromDB_CRL
from database.storage.x509Storage import writeToDB_DSC, readFromDB_DSC

from typing import Dict


from pymrtd import ef
from pymrtd.pki.ml import CscaMasterList
from database.storage.storageManager import Connection

from settings import config

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

class Builder:
    """Building database structures and connections between certificates"""

    def __init__(self, cscaFile, dscCrlFile):
        """CSCAfile and dscCrlFIle need to be in ldif format - downloaded from ICAO website"""
        conn = Connection(config["database"]["user"], config["database"]["pass"], config["database"]["db"])
        #self.parseDscCrlFile(dscCrlFile, conn)
        self.parseCSCAFile(cscaFile, conn)

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


    def parseCSCAFile(self, CSCAFile, connection: Connection):
        """Parsing CSCA file"""
        parser = LDIFParser(CSCAFile)
        for dn, entry in parser.parse():
            if 'CscaMasterListData' in entry:
                masterList = CscaMasterList(*entry['CscaMasterListData'])
                #verify masterlist - if failed it returns exception
                masterList.verify()

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

                    verify_and_write_csca(csca, issuing_cert, out_dir)

                for csca in skipped_cscas:
                    issuer_cert = get_issuer_cert(csca, cscas)
                    if issuer_cert is None:
                        debug.("Could not verify signature of CSCA C={} SerNo={}. Issuing CSCA not found!"
                                      .format(csca.subject.native['country_name'], format_cert_sn(csca)))
                        with get_ofile_for_csca(csca, out_dir.joinpath('unverified')) as f:
                            f.write(csca.dump())
                    else:
                        verify_and_write_csca(csca, issuer_cert, out_dir)

        ml = CscaMasterList(CSCAFile)
        r = 9
