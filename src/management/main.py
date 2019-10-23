'''
    File name: main.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

from management.builder import Builder


DSC_CRL = open('C://Users/nejko/Desktop/ZeroPass/B1/random/parseCSCAandCRL/data/icaopkd-001-dsccrl-003749.ldif', 'rb')
CSCA = open('C://Users/nejko/Desktop/ZeroPass/B1/random/parseCSCAandCRL/data/icaopkd-002-ml-000123.ldif', 'rb')

parse = Builder(CSCA, DSC_CRL)
re = 9
