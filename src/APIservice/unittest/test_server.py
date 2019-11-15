#!/usr/bin/python
import argparse, os, ssl, sys, coloredlogs, logging
from pathlib import Path

_script_path = Path(os.path.dirname(sys.argv[0]))
sys.path.append(str(_script_path / Path("../../")))

from datetime import datetime, timedelta
from settings import *
from APIservice.api import PassIdApiServer
from APIservice import proto
from pymrtd import ef



class DevProto(proto.PassIdProto):
    def __init__(self, storage: proto.StorageAPI, cttl: int, fc: bool, no_tcv: bool):
        super().__init__(storage, cttl)
        self._fc = fc
        self._no_tcv = no_tcv

    def createNewChallenge(self) -> proto.Challenge:
        if self._fc:
            now = datetime.utcnow()
            c = proto.Challenge.fromhex("47E4EE7F211F73265DD17658F6E21C1318BD6C81F37598E20A2756299542EFCF")
            self._db.addChallenge(c, now)
            return c
        return super().createNewChallenge()

    def _get_account_expiration(self, uid: proto.UserId):
        return datetime.utcnow() + timedelta(minutes=1)

    def validateCertificatePath(self, sod: ef.SOD):
            if not self._no_tcv:
                super().validateCertificatePath(sod)
            else:
                self._log.warning("Skipping verification of eMRTD certificate trustchain")
    
class DevApiServer(PassIdApiServer):
    def __init__(self, db: proto.StorageAPI, config: Config, fc=False, no_tcv=False):
        super().__init__(db, config)
        self._proto = DevProto(db, config.challenge_ttl, fc, no_tcv)


def main():

    # Set-up logging
    coloredlogs.install(level='DEBUG', 
        fmt='[%(asctime)s] %(name)s %(levelname)s %(message)s', 
        field_styles={
            'asctime': {'color': 'white'},
            'levelname': {'color': 'white', 'bold': True}
        },
        level_styles={
            'critical': {'color': 'red', 'bright': True},
            'debug': {'color': 'black', 'bright': True},
            'error': {'color': 'red', 'bright': True, 'bright': True},
            'info': {},
            'notice': {'color': 'magenta'},
            'spam': {'color': 'green', 'faint': True},
            'success': {'color': 'green', 'bright': True, 'bold': True},
            'verbose': {'color': 'blue'}, 'warning': {'color': 'yellow'}
    })

    fh = logging.FileHandler("server.log")
    fh.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '[%(asctime)s] %(name)s %(levelname)s %(message)s')
    fh.setFormatter(formatter)

    l = logging.getLogger("passid.server")
    l.addHandler(fh)

    l.info("Starting new server session ...")
    l.debug("run arguments: {}".format(sys.argv[1:]))

    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

    # Set-up cmd parameters
    ap = argparse.ArgumentParser()
    ap.add_argument("--challenge-ttl", default=300,
        type=int, help="number of seconds until requested challenge expires")

    ap.add_argument("-c", "--cert", default=str(_script_path / "tls/passid_server.cer"),
        type=str, help="server TLS certificate")

    ap.add_argument("--db-user", default="",
        type=str, help="database user name")

    ap.add_argument("--db-pwd", default="",
        type=str, help="database password")

    ap.add_argument("--db-name", default="",
        type=str, help="database name")

    ap.add_argument("-dev", default=False,
        action='store_true', help="start development version of server")

    ap.add_argument("-dev-fc", default=False,
        action='store_true', help="dev option: use pre-set fixed challenge instead of random generated")

    ap.add_argument("-dev-no-tcv", default=False,
        action='store_true', help="dev option: do not verify eMRTD PKI trust-chain")

    ap.add_argument("-k", "--key", default=str(_script_path / "tls/server_key.pem"),
        type=str, help="server TLS private key")

    ap.add_argument("-m", "--mdb", default=False,
        type=str, help="use MemoryDB for database. --db-* args will be ignored")

    ap.add_argument("-no-tls", default=False,
        action='store_true', help="do not use secure TLS connection")

    ap.add_argument("-p", "--port", default=8080,
        type=int, help="server listening port")

    ap.add_argument("-u", "--url", default='0.0.0.0',
        type=str, help="server http address")


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
        web_app=None,
        challenge_ttl = args['challenge_ttl']
    )

    if args['mdb']:
        db  = proto.MemoryDB()
    else:
        db = proto.DatabaseAPI(config.database.user, config.database.pwd, config.database.db)


    # Setup and run server
    if args["dev"]:
        sapi = DevApiServer(db, config, args['dev_fc'], args['dev_no_tcv'])
    else:
        sapi = PassIdApiServer(db, config)
    sapi.start()

if __name__ == "__main__":
    main()
