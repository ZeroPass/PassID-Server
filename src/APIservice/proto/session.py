import base64
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