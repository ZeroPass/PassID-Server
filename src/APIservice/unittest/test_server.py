#!/usr/bin/python
import sys, os
from pathlib import Path
sys.path.append(str(Path(os.path.dirname(sys.argv[0])) / Path("../../")))

from datetime import datetime, timedelta
from settings import *
from APIservice.api import PassIdApiServer
from APIservice import proto

class TestProto(proto.PassIdProto):
    def createNewChallenge(self) -> proto.Challenge:
        now = datetime.utcnow()
        c = proto.Challenge.fromhex("47E4EE7F211F73265DD17658F6E21C1318BD6C81F37598E20A2756299542EFCF")
        self._db.addChallenge(c, now)
        return c

    def _get_account_expiration(self, uid: proto.UserId):
        return datetime.utcnow() + timedelta(minutes=1)
    
class TestApiServer(PassIdApiServer):
    def __init__(self, db: proto.StorageAPI, config: Config):
        super().__init__(db, config)
        self._proto = TestProto(db, config.challenge_ttl)

def main():
    test_configs = Config( 
        database = DbConfig(
            user = "",
            pwd  = "",
            db   = ""
        ),
        api_server = ServerConfig(
            host = "localhost",
            port = 8080
        ),
        challenge_ttl = 60 #1 minute
    )


    #mdb  = proto.MemoryDB()
    mdb = proto.DatabaseAPI#(test_configs.database.user, test_configs.database.pwd, test_configs.database.db)
    sapi = TestApiServer(mdb, test_configs)
    sapi.start()

if __name__ == "__main__":
    main()
