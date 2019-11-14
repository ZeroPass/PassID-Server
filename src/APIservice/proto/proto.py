from datetime import datetime, timedelta

import logging
from typing import List, Tuple, Union

from pymrtd.pki.x509 import DocumentSignerCertificate
from .challenge import CID, Challenge
from .db import StorageAPI
from .session import SessionKey
from .user import UserId

from database.storage.accountStorage import AccountStorage

from pymrtd import ef
from pymrtd.pki.keys import AAPublicKey, SignatureAlgorithm


class ProtoError(Exception):
    """ General protocol exception """
    code = 400

class PeAccountConflict(ProtoError):
    """ User account error """
    code = 409

class PeChallengeExpired(ProtoError):
    """ Challenge has expired """
    code = 498

class PeCredentialsExpired(ProtoError):
    """ Challenge has expired """
    code = 498

class PeMissigParam(ProtoError):
    """ Missing protocol parameter """
    code = 422

class PePreconditionFailed(ProtoError):
    """ 
    One or more condition in verification of emrtd PKI truschain failed.
    Or when verifying SOD contains specific DG e.g.: DG1
    """
    code = 412

class PePreconditionRequired(ProtoError):
    """ 
    Required preconditions that are marked as optional.
    e.g.: at registration dg14 maight be required or at login dg1 could be required
    """
    code = 428


class PeSigVerifyFailed(ProtoError):
    """ Challenge signature verification error """
    code = 401




class PassIdProto:

    def __init__(self, storage: StorageAPI, cttl: int):
        self.cttl = cttl
        self._db = storage
        self._log = logging.getLogger("passid.proto")
        logging.SUCCESS = 25  # between WARNING and INFO
        logging.addLevelName(logging.SUCCESS, 'SUCCESS')
        setattr(self._log, 'success', lambda message, *args: self._log._log(logging.SUCCESS, message, args))

    def createNewChallenge(self) -> Challenge:
        now = datetime.utcnow()
        c   = Challenge.generate(now)
        self._db.addChallenge(c, now)
        return c

    def register(self, dg15: ef.DG15, sod: ef.SOD, cid: CID, csigs: List[bytes], dg14: ef.DG14 = None) -> Tuple[UserId, SessionKey, datetime]:
        """
        Register new user account-

        :param dg15: eMRTD DataGroup file 15
        :param sod: eMRTD Data Security Object
        :param cid: Challenge id
        :param csigs: List of signatures made over challenge chunks
        :param dg14: (Optional) eMRTD DataGroup file 14
        :return: Tuple of user id, session key and session expiration time
        """
        # 1. Verify account doesn't exist yet
        aaPubKey = dg15.aaPublicKey
        uid      = UserId.fromAAPublicKey(aaPubKey)

        if self._db.accountExists(uid):
            et = self._db.getAccountExpiry(uid)
            if not self._has_expired(et, datetime.utcnow()):
                raise PeAccountConflict("Account already registered")
            self._log.info("Account has expired, registering new credentials")

        # 2. Verify emrtd trust chain
        self._verify_emrtd_trustchain(sod, dg14, dg15)
        
        # 3. Verify challenge authentication
        sigAlgo = None
        if dg14 is not None:
            sigAlgo = dg14.aaSignatureAlgo

        if aaPubKey.isEcKey() and dg14 is None:
            raise PePreconditionRequired("DG14 required")

        self._verify_challenge(cid, aaPubKey, csigs, sigAlgo)
        self._db.deleteChallenge(cid) # Verifying has succeeded, delete challenge from db

        # 4. Insert account into db
        et = self._get_account_expiration(uid)

        a = AccountStorage(uid, sod, aaPubKey, sigAlgo, None, et)
        self._db.addOrUpdateAccount(a)

        # 5. Generate dummy session key and return results
        sk = SessionKey.generate()
        return (uid, sk, et)

    def login(self, uid: UserId,  cid: CID, csigs: List[bytes], dg1: ef.DG1 = None) -> Tuple[SessionKey, datetime]:
        """
        Register new user account-

        :param uid: User id
        :param cid: Challenge id
        :param csigs: List of signatures made over challenge chunks
        :param dg1: (Optional) eMRTD DataGroup file 1
        :return: Tuple of session key and session expiration time
        """

        # Get account
        a = self._db.getAccount(uid)
        a.loginCount += 1

        # 1. Require DG1 if login count is gt 1
        if a.loginCount > 1 and a.dg1 is None and dg1 is None:
            raise PePreconditionRequired("File DG1 required")

        # 2. If we got DG1 verify SOD contains its hash,
        #    and assign it to the account
        if dg1 is not None:
            sod = a.getSOD()
            self._log.info("Verifying SOD contains hash of received DG1 file")
            if not sod.ldsSecurityObject.contains(dg1):
                self._log.error("Invalid DG1 file!")
                raise PePreconditionFailed("Invalid DG1 file")
            else:
                self._log.success("Valid DG1 file!")
                a.setDG1(dg1)

        # 3. Verify account credentials haven't expired
        if self._has_expired(a.validUntil, datetime.utcnow()):
            raise PeCredentialsExpired("Account has expired")

        # 4. Verify challenge
        self._verify_challenge(cid, a.getAAPublicKey(), csigs, a.getSigAlgo())
        self._db.deleteChallenge(cid) # Verifying has succeeded, delete challenge from db

        # 5. Update account
        self._db.addOrUpdateAccount(a)

        # 6. Generate dummy session key and return it
        sk = SessionKey.generate()
        return (sk, a.validUntil)

    def _verify_challenge(self, cid: CID, aaPubKey: AAPublicKey, csigs: List[bytes], sigAlgo: SignatureAlgorithm = None ) -> None:
        """
        Check if signature is correct and the time frame is OK
        :raises:
            PeChallengeExpired: If challenge stored in db by cid has already expired 
            PeMissigParam: If aaPubKey is ec public key and no sigAlgo is provided
            PeSigVerifyFailed: If verifying signatures over chunks of challenge fails
        """

        try:
            self._log.info("Verifying challenge cid={}".format(cid))
            if aaPubKey.isEcKey() and sigAlgo is None:
                raise PeMissigParam("Missing param sigAlgo")

            c, t = self._db.getChallenge(cid)

            # Verify challenge expiration time
            def get_past(datetime: datetime):
                datetime = datetime.replace(tzinfo=None)
                return datetime - timedelta(seconds=self.cttl)

            ret = get_past(datetime.utcnow())
            t = t.replace(tzinfo=None)
            if self._has_expired(t, ret):
                self._db.deleteChallenge(cid)
                raise PeChallengeExpired("Challenge has expired")

            # Verify challenge signatures
            ccs = [c[0:8], c[8:16], c[16:24], c[24:32]]
            for idx, sig in enumerate(csigs):
                if not aaPubKey.verifySignature(ccs[idx], sig, sigAlgo):
                    raise PeSigVerifyFailed("Challenge signature verification failed")

            self._log.success("Challenge signed with eMRTD public key was successfully verified!")
        except:
            self._log.error("Challenge verification failed!")
            raise

    def _has_expired(self, t1: datetime, t2: datetime):
        return t1 < t2

    def _verify_emrtd_trustchain(self, sod: ef.SOD, dg14: Union[ef.DG14, None], dg15: ef.DG15) -> None:
        """"
        Verify eMRTD trust chain from eMRTD SOD to issuing CSCA 
        :raises: An exception is risen if any part of trust chain verification fails
        """

        assert isinstance(sod, ef.SOD)
        assert isinstance(dg14, (ef.DG14, type(None)))
        assert isinstance(dg15, ef.DG15)

        try:
            self._log.info("Verifying eMRTD certificate trustchain")
            if dg14 is not None and \
               not sod.ldsSecurityObject.contains(dg14):
                raise PePreconditionFailed("Invalid DG14 file")

            if not sod.ldsSecurityObject.contains(dg15):
                raise PePreconditionFailed("Invalid DG15 file")

            self.validateCertificatePath(sod)
            self._log.success("eMRTD certificate trustchain was successfully verified!")
        except:
            self._log.error("Failed to verify eMRTD certificate trustchain!")
            raise



    def getDSCbyIsserAndSerialNumber(self, issuer: str, serialNumber: int, sodCertificates) -> ():
        """Get DSC from SOD or from database if SOD is empty. It returns certificates in SOD and database."""
        DSCinSod = None
        DSCinDatabase = None
        for item in sodCertificates:
            if item.serial_number == serialNumber and item.issuer.human_friendly == issuer:
                DSCinSod = item
                break
        #item not found in SOD file, try to find it in database
        dbItem = self._db.getDSCbySerialNumber(issuer, str(serialNumber))
        if len(dbItem)> 0:
            DSCinDatabase = dbItem[0]
        return (DSCinSod, DSCinDatabase)

    def getDSCbySubjectKey(self, subjectKey: bytes, sodCertificates) -> []:
        """Get DSC from SOD or from database if SOD is empty. It returns certificates in SOD and database."""
        DSCinSod = None
        DSCinDatabase = None
        for item in sodCertificates:
            if item.key_identifier == subjectKey:
                DSCinSod = item
                break
        # item not found in SOD file, try to find it in database
        dbItem = self._db.getDSCbySubjectKey(subjectKey)
        if len(dbItem) > 0:
            DSCinDatabase = dbItem[0]
        return (DSCinSod, DSCinDatabase)

    def getCSCAByIssuerAndSerialNumber(self, issuer: str, serialNumber: int,):
        return self._db.getCSCAbySerialNumber(issuer, str(serialNumber))

    def getCSCABySubjectKey(self, subjectKey: bytes):
        return self._db.getCSCAbySubjectKey(subjectKey)

    def DSCtoCSCAvalidate(self, dsc: DocumentSignerCertificate):
        """Find CSCA and validate it"""
        if dsc.isValidOn(datetime.utcnow()) == False:
            raise PePreconditionFailed("DSC not valid anymore")

        csca = self.getCSCAByIssuerAndSerialNumber(dsc.issuer.human_friendly, dsc.serial_number) + \
               self.getCSCABySubjectKey(dsc.authorityKey)
        if len(csca) == 0:
            raise PePreconditionFailed("CSCA not found")

        obj = csca[0].getObject()
        # verify CSCA
        dsc.verify(obj)

    def validateCertificatePath(self, sod: ef.SOD):
        """Verification of issuer certificate from SOD file"""
        assert isinstance(sod, ef.SOD)

        includedDSC = sod.dsCertificates

        for sidx, signer in enumerate(sod.signers):
            foundDSC = (None, None)
            if signer.name == "issuer_and_serial_number":
                #sni = signer['sid'].chosen
                foundDSC = self.getDSCbyIsserAndSerialNumber(self.human_friendly(signer.native["issuer"]),
                                                             signer.native["serial_number"], includedDSC)
            elif signer.name == "subject_key_identifier":
                keyid = signer.native
                foundDSC = self.getDSCbySubjectKey(keyid, includedDSC)
            else:
                raise PePreconditionFailed("Unknown connection type to DSC ")

            if foundDSC[0] == None and foundDSC[1] == None:
                raise PePreconditionFailed("No DSC found")

            if foundDSC[0] == None:
                """no DSC found in SOD object, but found in database"""
                self.DSCtoCSCAvalidate(foundDSC[1].getObject())
                sod.verify(foundDSC[1].getObject())

            elif foundDSC[1] == None:
                """no DSC found in database, but found in SOD"""
                self.DSCtoCSCAvalidate(foundDSC[0])
                sod.verify()

            else:
                """ DSC found in SOD and database - same DSC"""
                self.DSCtoCSCAvalidate(foundDSC[0])
                sod.verify()



    def human_friendly(self, issuer: {}):
        """It returns friendly name of issuer Pattern follows format of asn1crypto library"""
        finalStr = ""
        #add common name
        finalStr += "Common Name: " + issuer["common_name"]
        #add organizational unit
        finalStr += ", Organizational Unit: " + issuer["organizational_unit_name"]
        #add organization
        finalStr += ", Organization: " + issuer["organization_name"]
        # add organization
        finalStr += ", Country: " + issuer["country_name"]
        return finalStr

    def _get_account_expiration(self, uid: UserId):
        """ Returns until the session is valid. """
        # Note: in ideal situation passport expiration date would be read from DG1 file and returned here.
        #       For now we return fix 15day period but should be calculated from the expiration time of DSC who signed accounts SOD.
        return datetime.utcnow() + timedelta(days=15)
