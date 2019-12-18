import base64
import hashlib
from typing import cast

from pymrtd.pki.keys import AAPublicKey

class UserIdError(Exception):
    pass

class UserId(bytes):
    """ Represents accounts userId"""

    _hash_algo = 'ripemd160'

    def __new__(cls, userId: bytes) -> "UserId":
        if not isinstance(userId, bytes) or \
            len(userId) != hashlib.new(cls._hash_algo).digest_size:
            raise UserIdError("Invalid userId data")
        return cast(UserId, super().__new__(cls, userId))  # type: ignore  # https://github.com/python/typeshed/issues/2630  # noqa: E501

    @staticmethod
    def fromAAPublicKey(pubKey: AAPublicKey) -> "UserId":
        assert isinstance(pubKey, AAPublicKey)
        h = hashlib.new(UserId._hash_algo)
        h.update(pubKey.dump())
        return UserId(h.digest())

    @staticmethod
    def fromhex(hexStr: str) -> "UserId":
        assert isinstance(hexStr, str)
        return UserId(bytes.fromhex(hexStr))

    @staticmethod
    def fromBase64(b64Str: str) -> "UserId":
        assert isinstance(b64Str, str)
        return UserId(base64.b64decode(b64Str))

    def toBase64(self):
        return str(base64.b64encode(self), 'ascii')