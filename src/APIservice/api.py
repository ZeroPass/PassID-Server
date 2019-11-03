import logging
import os
from typing import List

from werkzeug.wrappers import Request, Response
from werkzeug.serving import run_simple

from jsonrpc import Dispatcher, JSONRPCResponseManager as JRPCRespMgr
from jsonrpc.exceptions import JSONRPCDispatchException, JSONRPCServerError, JSONRPCInternalError

from APIservice import proto
from database.utils import *
from pymrtd import ef
from settings import Config

#before start you need to install json-rpc librarby (pip install json-rpc)


def try_deser(f):
    try:
        return f()
    except:
        raise proto.ProtoError("Bad parameter")

def _b64csigs_to_bcsigs(str_csigs: List[str]) -> List[bytes]:
    """ Convert list of base64 encoded signatures to list of byte signatures """
    csigs = []
    for scsig in str_csigs:
        csigs.append(try_deser(lambda: b64decode(scsig)))
    return csigs

class PassIdApiServer:
    """ PassID Api server """
    api_method_prefix = "passID"

    def __init__(self, db: proto.StorageAPI, config: Config):
        self._conf  = config.api_server
        self._proto = proto.PassIdProto(db, config.challenge_ttl)
        self._log   = logging.getLogger(PassIdApiServer.__name__)

        # Register rpc api methods
        self._req_disp = Dispatcher()
        def add_api_meth(f):
            # method format: <api_prefix>.<methodName>
            self._req_disp.add_method(f, "{}.{}".format(self.api_method_prefix, f.__name__))

        add_api_meth(self.ping)
        add_api_meth(self.getChallenge)
        add_api_meth(self.register)
        add_api_meth(self.login)

    def start(self):
            run_simple(self._conf.host, self._conf.port, self._create_calls)


# RPC API methods
    # API: passID.ping
    def ping(self, ping: int) -> dict:
        """ 
        Function returns challenge that passport needs to sign.
        Challenge is base64 encoded.
        """
        try:
            self._log.debug(":ping(): {}".format(ping))

            pong = int.from_bytes(os.urandom(4), 'big')
            self._log.debug(":ping(): Returning pong={}".format(pong))
            return { "pong": pong }
        except Exception as e:
            return self._handle_exception(e)

    # API: passID.getChallenge
    def getChallenge(self) -> dict:
        """ 
        Function returns challenge that passport needs to sign.
        Challenge is base64 encoded.
        """
        try:
            self._log.debug(":getChallenge(): Got request for challenge")
            c = self._proto.createNewChallenge()
            self._log.debug(":getChallenge(): Returning challenge={}".format(c.hex()))
            return {"cid": c.id, "challenge": c.toBase64() }
        except Exception as e:
            return self._handle_exception(e)

    # API: passID.register
    def register(self, dg15: str, sod: str, cid: str, csigs: List[str], dg14: str = None) -> dict:
        """ 
        Register new user. It returns back to the client userId which is publicKey address,
        session key and session expiration time.

        :param dg15: eMRTD DG15 file
        :param sod: eMRTD SOD file
        :param cid: Challenge id
        :param csigs: Challenge signatures
        :param dg14: eMRTD DG14 file (optional)
        :return: 
                 'uid'         - base64 encoded user id
                 'session_key' - base64 encoded session key
                 'expires'     - unix timestamp of time when session will expire
        """

        try:
            self._log.debug(":register(): Got register request")
            dg15  = try_deser(lambda: ef.DG15.load(b64decode(dg15)))
            sod   = try_deser(lambda: ef.SOD.load(b64decode(sod)))
            csigs = _b64csigs_to_bcsigs(csigs)
            if dg14 is not None:
                dg14 = try_deser(lambda: ef.DG14.load(b64decode(dg14)))

            uid, sk, set = self._proto.register(dg15, sod, proto.CID(cid), csigs, dg14)
            self._log.info(":register(): New user has been registered successfully. uid={} session expires: {}".format(uid2str(uid), set))
            print("expires", set.timestamp())
            return { "uid": uid.toBase64(), "session_key": sk.toBase64(), "expires": int(set.timestamp()) }
        except Exception as e:
            return self._handle_exception(e)

    # API: passID.login
    def login(self, uid: str, cid: proto.CID, csigs: List[str]) -> dict:
        """ 
        It returns back session key and session expiration time.

        :param uid: User id
        :param cid: Challenge id
        :param csigs: Challenge signatures
        :return:
                 'session_key' - base64 encoded session key
                 'expires'     - unix timestamp of time when session will expire
        """

        try:
            self._log.debug(":login(): Got login request uid={}".format(uid))
            uid   = try_deser(lambda: proto.UserId.fromBase64(uid))
            csigs = _b64csigs_to_bcsigs(csigs)

            sk, set = self._proto.login(uid, cid, csigs)
            self._log.info(":login(): User has successfully logged-in. uid={} session expires: {}".format(uid2str(uid), set))

            return { "session_key": sk.toBase64(), "expires": int(set.timestamp()) }
        except Exception as e:
            return self._handle_exception(e)

# Request handler
    @Request.application
    def _create_calls(self, request):
        """Create API calls"""
        response = JRPCRespMgr.handle(
            request.data,
            self._req_disp
        ).json
        return Response(response, mimetype='application/json')

    def _handle_exception(self, e: Exception)-> dict:
        if isinstance(e, proto.ProtoError):
            self._log.debug("Request proto error: {}".format(e))
            raise JSONRPCDispatchException(e.code, str(e))

        if isinstance(e, proto.SeEntryNotFound):
            self._log.debug("Request storage error: {}".format(e))
            raise JSONRPCDispatchException(404, str(e))
        
        self._log.error("Unhandled exception encountered, e={}".format(e))
        raise JSONRPCDispatchException(500, "Internal Server Error")
