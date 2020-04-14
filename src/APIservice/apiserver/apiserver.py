#!/usr/bin/python
import argparse, os, ssl, sys, coloredlogs
from pathlib import Path

_script_path = Path(os.path.dirname(sys.argv[0]))
sys.path.append(str(_script_path / Path("../../")))

import log
from datetime import datetime, timedelta
from settings import *
from APIservice.api import PassIdApiServer
from APIservice import proto
from pymrtd import ef
from pymrtd.pki import x509


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

    def _get_default_account_expiration(self):
        return proto.utils.time_now() + timedelta(minutes=1)

    def validateCertificatePath(self, sod: ef.SOD):
            if not self._no_tcv:
                super().validateCertificatePath(sod)
            else:
                self._log.warning("Skipping verification of eMRTD certificate trustchain")
    
class DevApiServer(PassIdApiServer):
    def __init__(self, db: proto.StorageAPI, config: Config, fc=False, no_tcv=False):
        super().__init__(db, config)
        self._proto = DevProto(db, config.challenge_ttl, fc, no_tcv)




def parse_args():
    # Set-up cmd parameters
    ap = argparse.ArgumentParser()
    ap.add_argument("--challenge-ttl", default=300,
        type=int, help="number of seconds before requested challenge expires")

    ap.add_argument("-c", "--cert", default=str(_script_path / "tls/passid_server.cer"),
        type=str, help="server TLS certificate")

    ap.add_argument("--db-user", default="",
        type=str, help="database user name")

    ap.add_argument("--db-pwd", default="",
        type=str, help="database password")

    ap.add_argument("--db-name", default="",
        type=str, help="database name")

    ap.add_argument("--dev", default=False,
        action='store_true', help="start development version of server")

    ap.add_argument("--dev-fc", default=False,
        action='store_true', help="dev option: use pre-set fixed challenge instead of random generated")

    ap.add_argument("--dev-no-tcv", default=False,
        action='store_true', help="dev option: do not verify eMRTD PKI trust-chain")

    ap.add_argument("-k", "--key", default=str(_script_path / "tls/server_key.pem"),
        type=str, help="server TLS private key")

    ap.add_argument("--log-level", default=0,
        type=int, help="logging level, [0=verbose, 1=debug, 2=info, 3=warn, 4=error]")

    ap.add_argument("--mdb", default=False,
        action='store_true', help="use MemoryDB for database. --db-* args will be ignored")

    ap.add_argument("--mdb-pkd", default=None,
        type=Path, help="path to eMRTD PKD root folder")

    ap.add_argument("--no-tls", default=False,
        action='store_true', help="do not use secure TLS connection")

    ap.add_argument("-p", "--port",
        type=int, help="server listening port")

    ap.add_argument("-u", "--url", default='0.0.0.0',
        type=str, help="server http address")

    args = vars(ap.parse_args())

    if args["log_level"] <= 0:
        args["log_level"] = log.VERBOSE
    elif args["log_level"] == 1:
        args["log_level"] = log.DEBUG
    elif args["log_level"] == 2:
        args["log_level"] = log.INFO
    elif args["log_level"] == 3:
        args["log_level"] = log.WARN
    elif args["log_level"] >= 4:
        args["log_level"] = log.ERROR

    if args['port'] is None:
        args['port'] = 80 if args['no_tls'] else 443

    return args

def init_log(logLevel):
    l = log.getLogger()
    coloredlogs.install(level=log.getLevelName(logLevel), 
        logger=l, 
        fmt='[%(asctime)s] %(levelname)-8s %(name)s %(message)s', 
        field_styles={
            'asctime': {'color': 'white'},
            'levelname': {'color': 'white', 'bold': True}
        },
        level_styles={
            'verbose': {'color': 'black', 'bright': True},
            'debug': {},
            'info': {'color': 'cyan', 'bright': True},
            'warning': {'color': 'yellow'},
            'error': {'color': 'red', 'bright': True},
            'critical': {'color': 'red', 'bright': True},
            'notice': {'color': 'magenta'},
            'spam': {'color': 'green', 'faint': True},
            'success': {'color': 'green', 'bright': True, 'bold': True},
    })

    log.getLogger('requests').setLevel(log.WARN)
    log.getLogger('urllib3').setLevel(log.WARN)

    fh = log.FileHandler("server.log")
    fh.setLevel(logLevel)
    formatter = log.Formatter(
        '[%(asctime)s] %(levelname)-8s %(name)s %(message)s'
    )
    fh.setFormatter(formatter)
    l.addHandler(fh)

def load_pkd_to_mdb(mdb: proto.MemoryDB, pkd_path: Path):
    l = log.getLogger('passid.api.server')
    l.info("Loading PKD certificates into mdb ...")
    cert_count = 0
    for cert in pkd_path.rglob('*.cer'):
        try:
            l.verbose("Loading certificate: {}".format(cert))
            cfd = cert.open('rb')
            cert = x509.Certificate.load(cfd.read())

            ku = cert.key_usage_value.native
            if cert.ca and 'key_cert_sign' in ku:
                cert.__class__ = x509.CscaCertificate
                mdb.addCscaCertificate(cert)
                cert_count+=1
            elif 'digital_signature' in ku:
                cert.__class__ = x509.DocumentSignerCertificate
                mdb.addDscCertificate(cert)
                cert_count+=1
        except Exception as e:
            l.warning("Could not load certificate '{}'".format(cert))
    l.info("{} certificates loaded into mdb.".format(cert_count))


def main():
    args = parse_args()

    init_log(args['log_level'])
    l = log.getLogger('passid.api.server')
    l.info("Starting new server session ...")
    l.debug("run parameters: {}".format(sys.argv[1:]))

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
        if args['mdb_pkd'] and not args['dev_no_tcv']:
            load_pkd_to_mdb(db, args['mdb_pkd'])
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
