'''
    File name: challengeStorage.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from APIservice.proto.challenge import Challenge
from datetime import datetime

class ChallengeStorage(object):
    """Class for interaction between code structure and database"""

    def __init__(self):
        self.id = None
        self.challenge = None
        self.createTime = None

    @staticmethod
    def fromChallenge(challenge: Challenge, timedate: datetime) -> "ChallengeStorage":
        assert isinstance(challenge, Challenge)
        cs            = ChallengeStorage()
        cs.id         = challenge.id
        cs.challenge  = challenge.toBase64()
        cs.createTime = timedate
        return cs

    def getChallenge(self) -> Challenge:
        return Challenge.fromBase64(self.challenge)