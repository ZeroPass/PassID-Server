import base64, hmac, hashlib
from typing import cast
import os

from cryptography.hazmat.primitives.hashes import Hash, SHA512_256
from cryptography.hazmat.backends import default_backend


class SessionKeyError(Exception):
    pass

class SessionKey(bytes):
    """ Demo class which could represent session auth/decrypt key """

    _hash_algo = SHA512_256

    def __new__(cls, key: bytes) -> "SessionKey":
        if isinstance(key, bytes):
            if len(key) != cls._hash_algo.digest_size:
                raise SessionKeyError("Invalid session key length")
            return cast(SessionKey, super().__new__(cls, key))  # type: ignore  # https://github.com/python/typeshed/issues/2630  # noqa: E501
        else:
            raise SessionKeyError("Invalid session key type")

    @staticmethod
    def fromhex(hexStr: str) -> "SessionKey":
        assert isinstance(hexStr, str)
        return SessionKey(bytes.fromhex(hexStr))

    @staticmethod
    def fromBase64(b64Str: str) -> "SessionKey":
        assert isinstance(b64Str, str)
        return SessionKey(base64.b64decode(b64Str))

    def toBase64(self):
        return str(base64.b64encode(self), 'ascii')

    @staticmethod
    def generate() -> "SessionKey":
        rs = os.urandom(SessionKey._hash_algo.digest_size)
        h = Hash(SessionKey._hash_algo(), backend=default_backend())
        h.update(rs)
        return SessionKey(h.finalize())


class Session:
    def __init__(self, key: SessionKey, nonce: int = 0):
        assert isinstance(key, SessionKey)
        assert isinstance(nonce, int)
        assert  -1 < nonce <= 0xFFFFFFFF
        self.__key   = key
        self.__nonce = nonce

    @property
    def key(self):
        return self.__key

    @property
    def nonce(self):
        return self.__nonce

    def getMAC(self, data):
        n = self.__get_encoded_nonce()
        self.__increment_nonce()
        return hmac.new(
            key=self.__key,
            msg= n + data,
            digestmod=hashlib.sha256
        ).digest()

    def verifyMAC(self, data, mac):
        cmac = self.getMAC(data)
        return hmac.compare_digest(mac, cmac)

    def fromBytes(rawSession: bytes) -> "Session":
        assert isinstance(rawSession, bytes)

        dsize = SessionKey._hash_algo.digest_size
        key = SessionKey(rawSession[0:dsize])
        nonce = int.from_bytes(rawSession[dsize:], byteorder='big')  
        return Session(key, nonce)

    def bytes(self) -> bytes:
        return self.__key + self.__get_encoded_nonce()

    def __get_encoded_nonce(self):
        return self.__nonce.to_bytes(4, 'big')

    def __increment_nonce(self):
        self.__nonce += 1 
        if self.__nonce > 0xffffffff:
            self.__nonce = 0