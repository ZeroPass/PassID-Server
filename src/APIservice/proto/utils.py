import pycountry
from datetime import datetime, timedelta
from pymrtd.pki.x509 import Certificate

def time_now():
    return datetime.utcnow()

def has_expired(t1: datetime, t2: datetime):
    return t1 < t2

def format_cert_et(cert: Certificate, current_time: datetime = time_now()):
    """ """
    return "nvb=[{}] nva=[{}] now=[{}]".format(cert.notValidBefore, cert.notValidAfter, current_time)

def code_to_country_name(code: str):
    assert isinstance(code, str)
    code = code.upper()
    if len(code) == 2:
        c = pycountry.countries.get(alpha_2=code)
    else:
        c = pycountry.countries.get(alpha_3=code)
    if c is None:
        return code
    return c.name