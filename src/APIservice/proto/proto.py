from datetime import datetime, timedelta
import logging
from typing import List, Tuple, Union

from .challenge import CID, Challenge
from .db import StorageAPI
from .session import SessionKey
from .user import UserId

from pymrtd import ef
from pymrtd.pki import x509
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
    code = 401

class PePreconditionFailed(ProtoError):
    """ One or more condition in verification of emrtd PKI truschain failed """
    code = 412

class PeMissigParam(ProtoError):
    """ Missing protocol parameter """
    code = 422

class PeSigVerifyFailed(ProtoError):
    """ Challenge signature verification error """
    code = 401


class PassIdProto:

    def __init__(self, storage: StorageAPI, cttl: int):
        self.cttl = cttl
        self._log = logging.getLogger(PassIdProto.__name__)
        self._db = storage

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
            raise PeMissigParam("Missing param dg14")

        self._verify_challenge(cid, aaPubKey, csigs, sigAlgo)
        self._db.deleteChallenge(cid) # Verifying has succeeded, delete challenge from db

        # 4. Insert account into db
        et = self._get_account_expiration(uid)
        self._db.addOrUpdateAccount(aaPubKey, sigAlgo, sod, et)

        # 5. Generate dummy session key and return results
        sk = SessionKey.generate()
        return (uid, sk, et)

    def login(self, uid: UserId,  cid: CID, csigs: List[bytes]) -> Tuple[SessionKey, datetime]:
        """
        Register new user account-

        :param uid: User id
        :param cid: Challenge id
        :param csigs: List of signatures made over challenge chunks
        :return: Tuple of session key and session expiration time
        """

        aaPubKey, sigAlgo, et = self._db.getAccountCredentials(uid)

        # 1. Verify account credentials haven't expired
        if self._has_expired(et, datetime.utcnow()):
            raise PeCredentialsExpired("Account credentials have expired")

        # 2. Verify challenge
        self._verify_challenge(cid, aaPubKey, csigs, sigAlgo)
        self._db.deleteChallenge(cid) # Verifying has succeeded, delete challenge from db

        # 3. Generate dummy session key and return results
        sk = SessionKey.generate()
        return (sk, et)

    def _verify_challenge(self, cid: CID, aaPubKey: AAPublicKey, csigs: List[bytes], sigAlgo: SignatureAlgorithm = None ) -> None:
        """
        Check if signature is correct and the time frame is OK
        :raises:
            PeChallengeExpired: If challenge stored in db by cid has already expired 
            PeMissigParam: If aaPubKey is ec public key and no sigAlgo is provided
            PeSigVerifyFailed: If verifying signatures over chunks of challenge fails
        """
        if aaPubKey.isEcKey() and sigAlgo is None:
            raise PeMissigParam("Missing param sigAlgo")

        self._log.debug("Getting challenge from database cid={}".format(cid))
        c, t = self._db.getChallenge(cid)

        # Verify challenge expiration time
        def get_past(datetime: datetime):
            return datetime - timedelta(seconds=self.cttl)

        if self._has_expired(t, get_past(datetime.utcnow())):
            self._db.deleteChallenge(cid)
            raise PeChallengeExpired("Challenge has expired")

        # Verify challenge signatures
        self._log.debug("Verifying challenge signatures")
        ccs = [c[0:8], c[8:16], c[16:24], c[24:32]]
        for idx, sig in enumerate(csigs):
            if not aaPubKey.verifySignature(ccs[idx], sig, sigAlgo):
                raise PeSigVerifyFailed("Challenge signature verification failed")

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

        # TODO: get all needed certificates from database and verify trustchain from CSCA to SOD before verifying dg15 and dg14

        if dg14 is not None and \
           not sod.ldsSecurityObject.contains(dg14):
            raise PePreconditionFailed("Digest mismatch for file dg14")

        if not sod.ldsSecurityObject.contains(dg15):
            raise PePreconditionFailed("Digest mismatch for file dg15")

    def _get_account_expiration(self, uid: UserId):
        """ Returns until the session is valid. """
        # Note: in ideal situation passport expiration date would be read from DG1 file and returned here.
        #       For now we return fix 15day period but should be calculated from the expiration time of DSC who signed accounts SOD.
        return datetime.utcnow() + timedelta(days=15)
