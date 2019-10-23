'''
    File name: challengeStorage.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from database.storage.storageManager import Connection
from settings import logger
from datetime import datetime, timedelta
import hashlib
import uuid

class ChallengeStorageError(Exception):
    pass

class ChallengeStorage(object):
    """Class for interaction between code structure and database"""
    _id = None
    _challenge = None
    _createTime = None

    def __init__(self):
        self.id = None
        self.challenge = None
        self.createTime = None

    def create(self) -> dict:
        """Creating challenge"""
        bitSize = 64
        self.challenge = str(uuid.uuid4().int >> bitSize)
        self.id = hashlib.md5(str(self.challenge).encode('utf-8')).hexdigest()
        return {self.id: self.challenge}


    def checkSignature(self, signature: str) -> bool:
        """Check if signature is correct"""
        #TODO: write function
        return True

    def check(self, signature: str) -> bool:
        """Returns true if signature is correct, false viceversa"""
        if signature == None:
            raise ChallengeStorageError("Signature is empty")

        if self.checkSignature(signature) == False:
            raise ChallengeStorageError("Signature is not correct")
        return True

def getPast(datetime: datetime, sec: int):
    """Function remove seconds to given datetime"""
    return datetime - timedelta(seconds=sec)

def APIcheckSignature_DB(id: str, signature: str, timeFrameInSeconds: int, connection: Connection) -> bool:
    """Check if signature is correct and the time frame is OK"""
    try:
        logger.info("Getting id: " + id + "with signature: " + signature + " from database")
        result = connection.getSession().query(ChallengeStorage).filter(ChallengeStorage.id == id, #check if ID exists
                                                                ChallengeStorage.createTime > getPast(datetime.now(), timeFrameInSeconds) #check if current time is inside of time frame
                                                                ).all()


        if len(result) == 0:
            logger.info("Item not found in database or time limit exceeded")
            raise ChallengeStorageError("Item not found in database or time limit exceeded")

        if result[0].check(signature):
            logger.info("Signature is correct and time not exceeded.")

            #remove from database
            connection.getSession().delete(result[0])
            return True

    except Exception:
        raise ChallengeStorageError("Check signature process has failed")

