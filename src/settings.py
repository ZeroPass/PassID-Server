'''
    File name: settings.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

import logging
import ssl
from typing import NamedTuple 

#logging.basicConfig(level=logging.DEBUG) #waring, info, debug
#logger = logging.getLogger(__name__)

class DbConfig(NamedTuple):
    user: str
    pwd: str
    db: str

class ServerConfig(NamedTuple):
    host: str
    port: int
    ssl_ctx: ssl.SSLContext

class WebAppConfig(NamedTuple):
    host: str
    port: int

class Config(NamedTuple):
    database: DbConfig
    api_server: ServerConfig
    web_app: WebAppConfig
    challenge_ttl: int
