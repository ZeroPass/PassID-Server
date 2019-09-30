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

