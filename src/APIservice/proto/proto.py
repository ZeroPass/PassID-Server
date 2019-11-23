from datetime import datetime, timedelta
from typing import List, Tuple, Union

from asn1crypto.x509 import Name

from .challenge import CID, Challenge
from .db import StorageAPI
from .session import Session, SessionKey
from .user import UserId

from database.storage.accountStorage import AccountStorage

import log

from pymrtd import ef
from pymrtd.pki.keys import AAPublicKey, SignatureAlgorithm
from pymrtd.pki.x509 import Certificate, CscaCertificate, DocumentSignerCertificate


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

class PeMacVerifyFailed(ProtoError):
    """ Session mac verification error """
    code = 401

def currentTime():
    return datetime.utcnow()

class PassIdProto:

    def __init__(self, storage: StorageAPI, cttl: int):
        self.cttl = cttl
        self._db = storage
        self._log = log.getLogger("passid.proto")

    def createNewChallenge(self) -> Challenge:
        now = currentTime()
        c   = Challenge.generate(now)
        self._db.addChallenge(c, now)
        self._log.debug("New challenge created cid={}".format(c.id))
        return c

    def cancelChallenge(self, cid: CID) -> Union[None, dict]:
        self._db.deleteChallenge(cid)
        self._log.debug("Challenge was canceled cid={}".format(cid))

    def register(self, dg15: ef.DG15, sod: ef.SOD, cid: CID, csigs: List[bytes], dg14: ef.DG14 = None) -> Tuple[UserId, SessionKey, datetime]:
        """
        Register new user account.

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
            if not self.__has_expired(et, currentTime()):
                raise PeAccountConflict("Account already registered")
            self._log.debug("Account has expired, registering new credentials")

        # 2. Verify emrtd PKI trust chain
        self.__verify_emrtd_trustchain(sod, dg14, dg15)
        
        # 3. Verify challenge authentication
        sigAlgo = None
        if dg14 is not None:
            sigAlgo = dg14.aaSignatureAlgo

        if aaPubKey.isEcKey() and dg14 is None:
            raise PePreconditionRequired("DG14 required")

        self.__verify_challenge(cid, aaPubKey, csigs, sigAlgo)
        self._db.deleteChallenge(cid) # Verifying has succeeded, delete challenge from db

        # 4. Generate session key and session
        sk = SessionKey.generate()
        s  = Session(sk)

        # 5. Insert account into db
        et = self.__get_account_expiration(uid)
        a = AccountStorage(uid, sod, aaPubKey, sigAlgo, None, s, et)
        self._db.addOrUpdateAccount(a)

        self._log.debug("New account created: uid={}".format(uid.hex()))
        if len(sod.dsCertificates) > 0:
            self._log.debug("Issuing country of account's eMRTD: {}".format(sod.dsCertificates[0].issuerCountry))
        self._log.verbose("vaild_until={}".format(a.validUntil))
        self._log.verbose("login_count={}".format(a.loginCount))
        self._log.verbose("dg1=None")
        self._log.verbose("pubkey={}".format(a.aaPublicKey.hex()))
        self._log.verbose("sigAlgo={}".format("None" if dg14 is None else a.sigAlgo.hex()))
        self._log.verbose("session={}".format(s.bytes().hex()))

        # 6. Return user id, session key and session expiry date
        return (uid, sk, et)

    def login(self, uid: UserId,  cid: CID, csigs: List[bytes], dg1: ef.DG1 = None) -> Tuple[SessionKey, datetime]:
        """
        Login user and return session key.

        :param uid: User id
        :param cid: Challenge id
        :param csigs: List of signatures made over challenge chunks
        :param dg1: (Optional) eMRTD DataGroup file 1
        :return: Tuple of session key and session expiration time
        """
        # Get account
        a = self._db.getAccount(uid)

        # 1. Require DG1 if login count is gt 1
        self._log.debug("Logging-in account with uid={} login_count={}".format(uid.hex(), a.loginCount))
        if a.loginCount > 1 and a.dg1 is None and dg1 is None:
            self._log.error("Can't proceed login due to max no. of anonymous logins and no DG1 file provided!")
            raise PePreconditionRequired("File DG1 required")

        # 2. If we got DG1 verify SOD contains its hash,
        #    and assign it to the account
        if dg1 is not None:
            self._log.debug("Verifying received DG1(surname={} name={}) file is valid ...".format(dg1.mrz.surname, dg1.mrz.name))
            sod = a.getSOD()
            self.__verify_sod_contains_hash_of(sod, dg1)
            a.setDG1(dg1)

        # 3. Verify account credentials haven't expired
        if self.__has_expired(a.validUntil, currentTime()):
            raise PeCredentialsExpired("Account has expired")

        # 4. Verify challenge
        self.__verify_challenge(cid, a.getAAPublicKey(), csigs, a.getSigAlgo())
        self._db.deleteChallenge(cid) # Verifying has succeeded, delete challenge from db

        # 5. Generate session key and session
        sk = SessionKey.generate()
        s  = Session(sk)
        a.setSession(s)

        # 6. Update account
        a.loginCount += 1
        self._db.addOrUpdateAccount(a)
        if dg1 is not None:
            self._log.info("File DG1(surname={} name={}) issued by country '{}' is now tied to eMRTD pubkey={}"
                     .format(dg1.mrz.surname, dg1.mrz.name, dg1.mrz.country, a.aaPublicKey.hex()))

        # 7. Return session key and session expiry date
        self._log.debug("User has successfully logged-in. uid={} session_expires: {}".format(uid.hex(), a.validUntil))
        self._log.verbose("session={}".format(s.bytes().hex()))
        return (sk, a.validUntil)

    def sayHello(self, uid, mac):
        """
        Return greeting message based on whether user being anonymous or not.

        :param uid: User id
        :param mac: session mac over function name and uid
        :return: Greeting message
        """
        # Get account
        a = self._db.getAccount(uid)

        # 1. verify session mac
        data = "sayHello".encode('ascii') + uid
        self.__verify_session_mac(a, data, mac)

        # 2. return greetings
        msg = "Hi, anonymous!"
        dg1 = a.getDG1()
        if dg1 is not None:
            msg = "Hi, {} {}!".format(dg1.mrz.surname, dg1.mrz.name)
        return msg

    def __verify_challenge(self, cid: CID, aaPubKey: AAPublicKey, csigs: List[bytes], sigAlgo: SignatureAlgorithm = None ) -> None:
        """
        Check if signature is correct and the time frame is OK
        :raises:
            PeChallengeExpired: If challenge stored in db by cid has already expired 
            PeMissigParam: If aaPubKey is ec public key and no sigAlgo is provided
            PeSigVerifyFailed: If verifying signatures over chunks of challenge fails
        """

        try:
            self._log.debug("Verifying challenge cid={}".format(cid))
            if aaPubKey.isEcKey() and sigAlgo is None:
                raise PeMissigParam("Missing param sigAlgo")

            c, cet = self._db.getChallenge(cid)

            # Verify challenge expiration time
            def get_past(datetime: datetime):
                datetime = datetime.replace(tzinfo=None)
                return datetime - timedelta(seconds=self.cttl)

            ret = get_past(currentTime())
            cet = cet.replace(tzinfo=None)
            if self.__has_expired(cet, ret):
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

    def __has_expired(self, t1: datetime, t2: datetime):
        return t1 < t2

    def __verify_emrtd_trustchain(self, sod: ef.SOD, dg14: Union[ef.DG14, None], dg15: ef.DG15) -> None:
        """"
        Verify eMRTD trust chain from eMRTD SOD to issuing CSCA 
        :raises: An exception is risen if any part of trust chain verification fails
        """
        assert isinstance(sod, ef.SOD)
        assert isinstance(dg14, (ef.DG14, type(None)))
        assert isinstance(dg15, ef.DG15)

        try:
            self._log.info("Verifying eMRTD trust chain ...")
            if dg14 is not None:
                self.__verify_sod_contains_hash_of(sod, dg14)

            self.__verify_sod_contains_hash_of(sod, dg15)
            self.__validate_certificate_path(sod)
            self._log.success("eMRTD trust chain was successfully verified!")
        except:
            self._log.error("Failed to verify eMRTD certificate trust chain!")
            raise

    def __get_dsc_by_isser_and_serial_number(self, issuer: Name, serialNumber: int, sod: ef.SOD) -> Tuple[Union[DocumentSignerCertificate, None], bool]:
        """
        Get DSC from SOD or from database if not found ind SOD.
        :param issuer:
        :param serialNumber:
        :param sod:
        :return: Pair of DSC/None and boolean whether DSC should be validated to CSCA certificate.
                 Note: DSC should be validated to CSCA only if DSC is found in SOD file.
                       DSC found in DB should be considered already validated.
        """
        # Try to find DSC in database
        dsc = self._db.getDSCbySerialNumber(issuer, serialNumber)
        if dsc is not None:
            return (dsc, False)

        # DSC not found in database, try to find it in SOD file
        for dsc in sod.dsCertificates:
            if dsc.serial_number == serialNumber and dsc.issuer == issuer:
                return (dsc, True) # DSC should be validated to issuing CSCA
        return (None, False)

    def __get_dsc_by_subject_key(self, subjectKey: bytes, sod: ef.SOD) -> Tuple[Union[DocumentSignerCertificate, None], bool]:
        """
        Get DSC from SOD or from database if not found ind SOD.
        :param subjectKey:
        :param sod:
        :return: Pair of DSC/None and boolean whether DSC should be validated to CSCA certificate.
                 Note: DSC should be validated to CSCA only if DSC is found in SOD file.
                       DSC found in DB should be considered as already validated.
        """
        # Try to find DSC in database
        dsc = self._db.getDSCbySubjectKey(subjectKey)
        if dsc is not None:
            return (dsc, False)

        # DSC not found in database, try to find it in SOD file
        for dsc in sod.dsCertificates:
            if dsc.subjectKey == subjectKey:
                return (dsc, True) # DSC should be validated to issuing CSCA
        return (None, False)

    def __validate_dsc_to_csca(self, dsc: DocumentSignerCertificate):
        """ Find DSC's issuing CSCA and validate DSC with it. """
        # 1. Get CSCA that issued DSC
        csca = None
        dsc_auth_key = dsc.authorityKey
        if dsc_auth_key is not None:
            self._log.verbose("Trying to find CSCA in DB by subject key. DSC auth_key={}".format(dsc_auth_key.hex()))
            csca = self._db.getCSCAbySubjectKey(dsc_auth_key)
            if csca is None: self._log.verbose("CSCA not found by DSC auth_key!")

        if csca is None:
            self._log.verbose("Trying to find CSCA in DB by DSC issuer field: [{}]".format(dsc.issuer.human_friendly))
            csca = self._db.getCSCAbySubject(dsc.issuer) 

        if csca is None:
            self._log.error("CSCA not found!")
            raise PePreconditionFailed("CSCA not found")
        self._log.verbose("Found CSCA fp={} county={}".format(csca.fingerprint[0:8], csca.issuerCountry))

        # 2. Verify CSCA expiration time
        self._log.verbose("Verifying CSCA expiration time. {}".format(self.__format_cert_et(csca)))
        if not csca.isValidOn(currentTime()):
            self._log.error("CSCA has expired!")
            raise PePreconditionFailed("CSCA has expired")

        # 3. verify CSCA really issued DSC
        self._log.verbose("Verifying CSCA issued DSC ...")
        dsc.verify(issuing_cert=csca)

    def __validate_certificate_path(self, sod: ef.SOD):
        """Verification of issuer certificate from SOD file"""
        self._log.debug("Validating path CSCA => DSC => SOD ...")
        assert isinstance(sod, ef.SOD)

        # Get DSCs certificates that signed SOD file. DSC is also validated to CSCA trust chain if necessary.
        dscs = []
        for sidx, signer in enumerate(sod.signers):
            if signer.name == "issuer_and_serial_number":
                #sni = signer['sid'].chosen
                signer = signer.chosen
                issuer = signer["issuer"]
                serial = signer["serial_number"].native
                self._log.verbose("Getting DSC which signed SOD by serial no.: {} and issuer: [{}]".format(serial, issuer.human_friendly))
                dsc, validateDSC = self.__get_dsc_by_isser_and_serial_number(
                    issuer,
                    serial,
                    sod
                )
            elif signer.name == "subject_key_identifier":
                keyid = signer.native
                self._log.verbose("Getting DSC which signed SOD by subject_key={}".format(keyid.hex()))
                dsc, validateDSC = self.__get_dsc_by_subject_key(keyid, sod)
            else:
                raise PePreconditionFailed("Unknown connection path from SOD to DSC")

            if dsc is None:
                raise PePreconditionFailed("No DSC found")

            self._log.verbose("Got DSC fp={} issuer_country={}, validating path to CSCA required: {}".format(dsc.fingerprint[0:8], dsc.issuerCountry, validateDSC))
            self._log.verbose("Verifying DSC expiration time. {}".format(self.__format_cert_et(dsc)))
            if not dsc.isValidOn(currentTime()):
                raise PePreconditionFailed("DSC has expired")
            elif validateDSC:
                self.__validate_dsc_to_csca(dsc) # validate CSCA has issued DSC
            dscs.append(dsc)

        # Verify DSCs signed SOD file
        self._log.verbose("Verifying DSC issued SOD ...")
        sod.verify(issuer_dsc_certs=dscs)

    def __verify_sod_contains_hash_of(self, sod: ef.SOD, dg: ef.DataGroup):
        assert isinstance(sod, ef.SOD)
        assert isinstance(dg, ef.DataGroup)

        self._log.debug("Verifying SOD contains matching hash of {} file ...".format(dg.number.native))
        if self._log.getEffectiveLevel() <= log.VERBOSE:
            sod_dghv = sod.ldsSecurityObject.dgHashes.find(dg.number)
            self._log.verbose("SOD contains hash of {} file: {}".format(dg.number.native, (sod_dghv is not None)))
            if sod_dghv is not None:
                hash_algo = sod.ldsSecurityObject.dgHashAlgo['algorithm'].native
                self._log.verbose("{} hash value of {} file in SOD: {}".format(hash_algo, dg.number.native, sod_dghv.hash.hex()))
                h = sod.ldsSecurityObject.getDgHasher()
                h.update(dg.dump())
                self._log.verbose("Actual {} hash value of {} file: {}".format(hash_algo, dg.number.native, h.finalize().hex()))

        # Validation of dg hash value in SOD
        if not sod.ldsSecurityObject.contains(dg):
            raise PePreconditionFailed("Invalid {} file".format(dg.number.native))
        self._log.debug("{} file is valid!".format(dg.number.native))

    def __get_account_expiration(self, uid: UserId):
        """ Returns until the session is valid. """
        # Note: in ideal situation passport expiration date would be read from DG1 file and returned here.
        #       For now we return fix 15day period but should be calculated from the expiration time of DSC who signed accounts SOD.
        return currentTime() + timedelta(days=15)

    def __verify_session_mac(self, a: AccountStorage, data: bytes, mac: bytes):
        """
        Check if mac is valid
        :raises:
            PeMacVerifyFailed: If mac is invalid
        """
        self._log.debug("Verifying session MAC ...")

        s = a.getSession()
        self._log.verbose("nonce: {}".format(s.nonce))
        self._log.verbose("data: {}".format(data.hex()))
        self._log.verbose("mac: {}".format(mac.hex()))

        success = s.verifyMAC(data, mac)
        self._log.debug("MAC successfully verified!")

        # Update account with new session once
        a.setSession(s)
        self._db.addOrUpdateAccount(a)

        if not success:
            raise PeMacVerifyFailed("Invalid session MAC")

    def __format_cert_et(self, cert: Certificate):
        return "nvb=[{}] nva=[{}] now=[{}]".format(cert.notValidBefore, cert.notValidAfter, currentTime())