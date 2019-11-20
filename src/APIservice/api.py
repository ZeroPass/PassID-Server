import os
from typing import List, Union

from werkzeug.wrappers import Request, Response
from werkzeug.serving import run_simple

from jsonrpc import Dispatcher, JSONRPCResponseManager as JRPCRespMgr
from jsonrpc.exceptions import JSONRPCDispatchException, JSONRPCServerError, JSONRPCInternalError

import log

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
        self._log   = log.getLogger("passid.api")

        # Register rpc api methods
        self.__init_api()

    def start(self):
        run_simple(self._conf.host, self._conf.port, self.__create_calls, ssl_context=self._conf.ssl_ctx, threaded=True)

    def passidapi(api_f):
        def wrapped_api_f(self, *args, **kwargs):
            self.__log_api_call(api_f, **kwargs)
            return api_f(self, *args, **kwargs)
        return wrapped_api_f

# RPC API methods
    # API: passID.ping
    @passidapi
    def ping(self, ping: int) -> dict:
        """ 
        Function returns challenge that passport needs to sign.
        Challenge is base64 encoded.
        """
        try:
            self._log.debug(":ping(): {}".format(ping))

            pong = int.from_bytes(os.urandom(4), 'big')
            self._log.debug("Returning pong={}".format(pong))
            return { "pong": pong }
        except Exception as e:
            return self.__handle_exception(e)

    # API: passID.getChallenge
    @passidapi
    def getChallenge(self) -> dict:
        """ 
        Function returns challenge that passport needs to sign.
        Challenge is base64 encoded.
        """
        try:
            self._log.debug(":getChallenge(): Got request for challenge")
            c = self._proto.createNewChallenge()
            self._log.debug("Returning cid={} challenge={}".format(c.id, c.hex()))
            return { "challenge": c.toBase64() }
        except Exception as e:
            return self.__handle_exception(e)

    # API: passID.cancelChallenge
    @passidapi
    def cancelChallenge(self, challenge: str) -> Union[None, dict]:
        """ 
        Function erases challenge from server.
        :param challenge: base64 encoded string
        :return: 
                 Nothing if success, else error
        """
        try:
            self._log.debug(":cancelChallenge(): Got request to cancel challenge")
            challenge = try_deser(lambda: proto.Challenge.fromBase64(challenge))
            self._proto.cancelChallenge(challenge.id)
            self._log.debug("Challenge was canceled cid={}".format(challenge.id))
            return None
        except Exception as e:
            return self.__handle_exception(e)

    # API: passID.register
    @passidapi
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
            dg15 = try_deser(lambda: ef.DG15.load(b64decode(dg15)))
            sod  = try_deser(lambda: ef.SOD.load(b64decode(sod)))
            cid  = try_deser(lambda: proto.CID.fromhex(cid))
            csigs = _b64csigs_to_bcsigs(csigs)
            if dg14 is not None:
                dg14 = try_deser(lambda: ef.DG14.load(b64decode(dg14)))

            uid, sk, set = self._proto.register(dg15, sod, cid, csigs, dg14)
            self._log.debug("New user has been registered successfully. uid={} session_expires: {}".format(uid2str(uid), set))
            return { "uid": uid.toBase64(), "session_key": sk.toBase64(), "expires": int(set.timestamp()) }
        except Exception as e:
            return self.__handle_exception(e)

    # API: passID.login
    @passidapi
    def login(self, uid: str, cid: str, csigs: List[str], dg1: str = None) -> dict:
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
            uid = try_deser(lambda: proto.UserId.fromBase64(uid))
            cid = try_deser(lambda: proto.CID.fromhex(cid))
            csigs = _b64csigs_to_bcsigs(csigs)
            if dg1 is not None:
                dg1 = try_deser(lambda: ef.DG1.load(b64decode(dg1)))

            sk, set = self._proto.login(uid, cid, csigs, dg1)
            self._log.debug("User has successfully logged-in. uid={} session_expires: {}".format(uid2str(uid), set))

            return { "session_key": sk.toBase64(), "expires": int(set.timestamp()) }
        except Exception as e:
            return self.__handle_exception(e)

# Request handler
    @Request.application
    def __create_calls(self, request):
        """Create API calls"""
        response = JRPCRespMgr.handle(
            request.data,
            self._req_disp
        ).json
        return Response(response, mimetype='application/json')

    def __handle_exception(self, e: Exception)-> dict:
        if isinstance(e, proto.ProtoError):
            self._log.debug("Request proto error: {}".format(e))
            raise JSONRPCDispatchException(e.code, str(e))

        if isinstance(e, proto.SeEntryNotFound):
            self._log.debug("Request storage error: {}".format(e))
            raise JSONRPCDispatchException(404, str(e))
        
        self._log.error("Unhandled exception encountered, e={}".format(e))
        raise JSONRPCDispatchException(500, "Internal Server Error")

    def __init_api(self):
        self._req_disp = Dispatcher()

        def add_api_meth(api_f, name):
            # method format: <api_prefix>.<methodName>
            passid_api_f = lambda *args, **kwargs: api_f(self, *args, **kwargs)
            self._req_disp.add_method(passid_api_f, "{}.{}".format(PassIdApiServer.api_method_prefix, name))

        # register methods with @passidapi decorator as rpc api handler
        import inspect
        meths = inspect.getmembers(PassIdApiServer, predicate=inspect.isfunction)
        for m in meths:
            if m[1].__name__ == "wrapped_api_f":
                add_api_meth(m[1], m[0])

    def __log_api_call(self, f, **kwargs):
        if self._log.level <= log.VERBOSE:
            self._log.verbose(":{}() =>".format(f.__name__))
            for a, v in kwargs.items():
                self._log.verbose(" {}: {}".format(a, v))