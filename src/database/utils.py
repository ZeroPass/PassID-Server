import base64
from APIservice.proto.user import UserId

def b64encode(data: bytes):
    assert isinstance(data, bytes)
    return str(base64.b64encode(data), 'ascii')

def b64decode(b64str: str):
    assert isinstance(b64str, str)
    return base64.b64decode(b64str)

def uid2str(uid: UserId) -> str:
    """ converts UserId to hex string as represented in database """
    return uid.hex()

def str2uid(struid: str) -> UserId:
    """ Returns UserId constructed from hex string """
    return proto.UserId.fromhex(struid)