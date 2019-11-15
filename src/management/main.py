'''
    File name: main.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from management.builder import Builder
from settings import *


DSC_CRL = open('C://Users/nejko/Desktop/ZeroPass/B1/random/parseCSCAandCRL/data/abc/icaopkd-001-dsccrl-003903.ldif', 'rb')
CSCA = open('C://Users/nejko/Desktop/ZeroPass/B1/random/parseCSCAandCRL/data/abc/icaopkd-002-ml-000131.ldif', 'rb')

config = Config(
        database=DbConfig(user="", pwd="", db=""),
        api_server=ServerConfig(host=None, port=None, ssl_ctx=None),
        web_app=WebAppConfig(host=None, port=None),
        challenge_ttl=0
    )

parse = Builder(CSCA, DSC_CRL, config)
re = 9
