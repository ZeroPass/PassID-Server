#!/usr/bin/python
import sys, os
from pathlib import Path

sys.path.append(str(Path(os.path.dirname(sys.argv[0])) / Path("../../")))

from datetime import datetime, timedelta
from settings import *
from APIservice.api import PassIdApiServer
from APIservice import proto


def main():
    test_configs = Config(
        database=DbConfig(
            user="",
            pwd="",
            db=""
        ),
        api_server=ServerConfig(
            host="localhost",
            port=8080
        ),
        challenge_ttl=60  # 1 minute
    )
    mdb = proto.DatabaseAPI(test_configs.database.user, test_configs.database.pwd, test_configs.database.db)
    sapi = PassIdApiServer(mdb, test_configs)
    sapi.start()


if __name__ == "__main__":
    main()
