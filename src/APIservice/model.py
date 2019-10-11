'''
    File name: model.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

class Model:
    """Set of functions to use it in the API (JSON-RPC)"""

    def getChallenge(self) -> bytes:
        """Function returns challenge that passport needs to sign"""

    def register(self, challengeId: bytes, signature: bytes, publicKey, sodData) -> bool:
        """Check if signature is correct on given server challenge (it was given in previous step)"""

    def login(self, publicKeyAddress, challengeId, signature) -> bool:


####################################################################

getChallenge:OUT: dict[challenge], expiration(utc time)

register: IN: challengeId, signature, public key, SOD data + personal data(optional)
        OUT: result(status)

register Additionaldata: like above but without SOD and PKA

login: in: public key address(ripmd 160 over public key), challengeId, signature
        OYT: result (status like HTTP codes)



##########################################################################

CRL: \
    -object
    -serial Number
    -subject key //not
    -authority key (CSCA - foreign key)
    -countrKey
    -start, end valid
    -signiture algorithm
    -signature hash algorithm
-SHA256 hash over whole object

DSC + CSCA:
    - revocatingCRLSerial number (if null not revocated, else CRL(serial Number))
    -object
    - Country
    - SerialNumber
    -subject key
    -authority key (CSCA could have it or not)
    -public key
    -PKI algorithm
    -signature algoritm
    -signature hash algorithm
    -is valid:start stop
    -is valid start stop(private key usage valid - when private key can make signatures)
    -SHA256 hash over whole object

    //only in csca
    -CRL distibution point (where are CRL stored)
    -subject basic data of issuer
    -subject/Issuer alternative name


@property
def issuerCountry(self) -> str:
    """Function returns country of CRL issuer """
    country = self.issuer.native['country_name']
    logger.debug("Getting country of CRL issuer: " + country)
    return country


@property
def size(self) -> int:
    """Function returns size of CRL"""
    size = len(self['tbs_cert_list']['revoked_certificates'])
    logger.debug("Getting size of CRL: " + size)
    return size


@property
def thisUpdate(self) -> datetime:
    """In certificate the field is 'this_update'"""
    this_update = self['tbs_cert_list']['this_update'].native
    logger.debug("CRL has been created on: " + str(this_update))
    return this_update


@property
def nextUpdate(self) -> datetime:
    """In certificate the field is 'next_update'"""
    next_update = self['tbs_cert_list']['next_update'].native
    logger.debug("Next CRL update: " + str(next_update))
    return next_update


@property
def signatureAlgorithm(self) -> str:
    """It returns signature algorithm"""
    sig_algo = self['signature_algorithm'].signature_algo
    logger.debug("Signature algorithm: " + sig_algo)
    return sig_algo


@property
def signatureHashAlgorithm(self) -> str:
    """It returns hash of signature algorithm"""
    hash_algo = self['signature_algorithm'].hash_algo
    logger.debug("Signature hash algorithm: " + hash_algo)
    return hash_algo


@property
def fingerprint(self) -> str:
    """SHA256 hash over CRL object"""
    fp = self.sha256.hex()
    logger.debug("Fingerprint of CRL object: " + fp)
    return fp
