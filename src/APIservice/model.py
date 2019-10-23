'''
    File name: model.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

#before start you need to install json-rpc librarby (pip install json-rpc)
#sudo apt-get install postgresql postgresql-contrib
#pip install sqlalchemy
#pip install psycopg2 sqlalchemy
#sudo -u postgres createuser --interactive


from werkzeug.wrappers import Request, Response
from werkzeug.serving import run_simple

from database.storage.storageManager import Connection

from jsonrpc import JSONRPCResponseManager, dispatcher
from database.storage.challengeStorage import ChallengeStorage, APIcheckSignature_DB, ChallengeStorageError
from database.storage.accountStorage import writeToDB_account, readFromDBwithPublicKeyAddress_account, AccountStorageError
from settings import *
from datetime import datetime, timedelta

class DatabaseAPIError(Exception):
    pass

class ModelError(Exception):
    pass

class DatabaseAPI:
    conn = None

    def __init__(self):
        """Creating connection to the database and initialization of main strucutres"""
        self.conn = Connection(config["database"]["user"], config["database"]["pass"], config["database"]["db"])

    def createChallenge(self) -> dict:
        """Create and save challenge"""

        #create challenge parameters
        challenge = ChallengeStorage()
        param = challenge.create()

        #save to database
        self.conn.getSession().add(challenge)
        self.conn.getSession().commit()

        return param

    def getValidUntil(self, SOD):
        """Return datetime certificate is valid"""
        #TODO: get real data from SOD
        return datetime.now() - timedelta(days=15)

    def register(self, challengeId: str, signature: str, publicKey: str, sodData: str) -> str:
        """API call: register"""
        #check signature
        APIcheckSignature_DB(challengeId, signature, config["registerTimeFrame"], self.conn)

        #save to database and return public key address
        validUntil = self.getValidUntil(sodData)
        return writeToDB_account(publicKey, validUntil, sodData, self.conn)

    #public key address(ripmd 160 over public key), challengeId, signature
    def login(self, challengeId: str, signature: str, publicKeyAddress: str) -> dict:
        """API call: login"""
        #check signature
        APIcheckSignature_DB(challengeId, signature, config["registerTimeFrame"], self.conn)
        #read from database
        return readFromDBwithPublicKeyAddress_account(publicKeyAddress, self.conn)


#database API creation
databaseAPI = DatabaseAPI()

@dispatcher.add_method
def getChallenge(self) -> dict:
    """Function returns challenge that passport needs to sign"""
    try:
        params = databaseAPI.createChallenge()
        for key, value in params.items():
            return {"success": 1, "id": key, "challenge": value}

        #item not found
        raise ModelError("Creation challengeId and value failed.")
    except DatabaseAPIError as e:
        return {"success": 0, "error:": 401, "detail": e}
    except ChallengeStorageError as e:
        return {"success": 0, "error:": 402, "detail": e}
    except Exception as e:
        return {"success": 0, "error:": 400, "detail": e}


@dispatcher.add_method
def register(self, challengeId: str, signature: str, publicKey: str, sodData: str) -> bool:
    """Check if signature is correct on given server challenge (it was given in previous step)"""
    try:
        pka = databaseAPI.register(challengeId, signature, publicKey, sodData)
        return {"success": 1, "publicKeyAddress": pka}
    except DatabaseAPIError as e:
        return {"success": 0, "error:": 401, "detail": e}
    except ChallengeStorageError as e:
        return {"success": 0, "error:": 402, "detail": e}
    except AccountStorageError as e:
        return {"success": 0, "error:": 403, "detail": e}
    except Exception as e:
        return {"success": 0, "error:": 400, "detail": e}


@dispatcher.add_method
def login(self, challengeId: str, signature: str, publicKey: str) -> bool:
    """Check if signature is correct on given server challenge (it was given in previous step)"""
    try:
        data = databaseAPI.login(challengeId, signature, publicKey)
        return {"success": 1,
                "hasAccess": 1,
                "validUntil": str(data.getValidUntil())}
    except DatabaseAPIError as e:
        return {"success": 0, "error:": 401, "detail": e}
    except ChallengeStorageError as e:
        return {"success": 0, "error:": 402, "detail": e}
    except AccountStorageError as e:
        return {"success": 0, "error:": 403, "detail": e}
    except Exception as e:
        return {"success": 0, "error:": 400, "detail": e}


class Application:
    """API server"""

    @Request.application
    def createCalls(self, request):
        """Create API calls"""
        response = JSONRPCResponseManager.handle(
            request.data, dispatcher)
        return Response(response.json, mimetype='application/json')


def test():
    """Test API model class. Call it when you need to test if API calls works"""
    import random
    publicKey = "publicKey" + str(random.randint(0,1000))
    #test registration
    a = getChallenge("")
    for key, value in a.items():
        if key == "id":
            result = register("", value, "signature", publicKey, "SOD")
            print(result)

    #test login
    b = getChallenge("")
    for key, value in b.items():
        if key == "id":
            result = login("", value, "signature", publicKey)
            print(result)
