#!/usr/bin/python
import argparse, os, ssl, sys
from pathlib import Path

_script_path = Path(os.path.dirname(sys.argv[0]))
sys.path.append(str(_script_path / Path("../../")))

from datetime import datetime, timedelta
from settings import *
from APIservice.api import PassIdApiServer
from APIservice import proto
from pymrtd import ef



class DevProto(proto.PassIdProto):
    def createNewChallenge(self) -> proto.Challenge:
        now = datetime.utcnow()
        c = proto.Challenge.fromhex("47E4EE7F211F73265DD17658F6E21C1318BD6C81F37598E20A2756299542EFCF")
        self._db.addChallenge(c, now)
        return c

    def _get_account_expiration(self, uid: proto.UserId):
        return datetime.utcnow() + timedelta(minutes=1)

    def validateCertificatePath(self, sod: ef.SOD):
            pass
    
class DevApiServer(PassIdApiServer):
    def __init__(self, db: proto.StorageAPI, config: Config):
        super().__init__(db, config)
        self._proto = DevProto(db, config.challenge_ttl)


def main():

    ap = argparse.ArgumentParser()

    ap.add_argument("-u", "--url", default='0.0.0.0',
        type=str, help="server http address")

    ap.add_argument("-p", "--port",
        type=int, help="server listening port")

    ap.add_argument("-dev", default=False,
        action='store_true', help="start development version of server. This will use pre-set fixed challenge instead of random generated")

    ap.add_argument("--challenge-ttl", default=300,
        type=int, help="number of seconds until requested challenge expires")

    ap.add_argument("-c", "--cert", default=str(_script_path / "tls/passid_server.cer"),
        type=str, help="server TLS certificate")

    ap.add_argument("-k", "--key", default=str(_script_path / "tls/server_key.pem"),
        type=str, help="server TLS private key")

    ap.add_argument("-no-tls", default=False,
        action='store_true', help="do not use secure TLS connection")

    ap.add_argument("-m", "--mdb", default=False,
        type=str, help="use MemoryDB for database")

    ap.add_argument("--db-user", default="",
        type=str, help="database user name")

    ap.add_argument("--db-pwd", default="",
        type=str, help="database password")

    ap.add_argument("--db-name", default="",
        type=str, help="database name")

    args = vars(ap.parse_args())
    if args['port'] is None:
        args['port'] = 80 if args['no_tls'] else 443

    ctx = None
    if not args['no_tls']:
        ctx = ssl.SSLContext( ssl.PROTOCOL_TLS_SERVER)
        ctx.options | ssl.OP_SINGLE_ECDH_USE | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1 | ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2
        ctx.load_cert_chain(args['cert'], args['key'])

    config = Config( 
        database = DbConfig(
            user = args['db_user'],
            pwd  = args['db_pwd'],
            db   = args['db_name']
        ),
        api_server = ServerConfig(
            host = args['url'],
            port = args['port'],
            ssl_ctx = ctx
        ),
        challenge_ttl = args['challenge_ttl']
    )

    if args['mdb']:
        db  = proto.MemoryDB()
    else:
        db = proto.DatabaseAPI(config.database.user, config.database.pwd, config.database.db)

    if args["dev"]:
        sapi = DevApiServer(db, config)
    else:
        sapi = PassIdApiServer(db, config)

    sapi.start()

if __name__ == "__main__":
    main()
