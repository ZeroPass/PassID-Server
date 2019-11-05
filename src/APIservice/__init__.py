#!/usr/bin/python
import sys, os
from pathlib import Path

sys.path.append(str(Path(os.path.dirname(sys.argv[0])) / Path("../../")))

from settings import *
from APIservice.api import PassIdApiServer
from APIservice import proto


def main():
    mdb = proto.DatabaseAPI(config.database.user, config.database.pwd, config.database.db)
    sapi = PassIdApiServer(mdb, config)
    sapi.start()

if __name__ == "__main__":
    main()
