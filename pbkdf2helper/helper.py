import base64
import hashlib
import hmac
import secrets
import string

"""
pbkdf2helper

This Python module implements the basic PBKDF2 Helper-function based on
hashlib.sha256 and hmac

Example:

>>> import pbkdf2helper
>>> encoded = pbkdf2helper.encode("secret", "sha256", pbkdf2helper.generate_salt(12), 1000)
>>> encoded
'sha256$1000$sooDhmF4$GloPulbaSfWsoIhU34mBzURTZTszCgfNoJ4myYcF1c4='

>>> pbkdf2helper.verify("secret", encoded)
True

>>> pbkdf2helper.split(encoded)
('sha256', '1000', 'sooDhmF4', 'GloPulbaSfWsoIhU53mBzUXMZTszCgfNoJ4myYcF1c4=')

>>> pbkdf2helper.generate_salt(12)
'f3a0bLXx'


copyright: (c) Copyright 2017 by Kungalex.
license: MIT, see LICENSE for more details.
"""


digest = hashlib.sha256
alphabet = string.ascii_letters + string.digits


def encode(password, algorithm, salt, iterations):
    """
    Encode a Password
    :param password: Password
    :param algorithm
    :param salt: Salt
    :param iterations: iterations
    :return: PBKDF2 hashed Password
    """
    hash = hashlib.pbkdf2_hmac(digest().name, password.encode(), salt.encode(), iterations)
    encoded = base64.b64encode(hash).decode('ascii').strip()
    return "%s$%d$%s$%s" % (algorithm, iterations, salt, encoded)


def verify(password, encoded):
    """
    Verify a Password
    :param password:
    :param encoded:
    :return: True or False
    """
    algorithm, iterations, salt, h = split(encoded)

    to_verify = encode(password, algorithm, salt, int(iterations))
    return hmac.compare_digest(to_verify.encode(), encoded.encode())


def split(encoded):
    """
    Split a PBKDF2 hashed Password into algorithm, iterations, salt and hash
    :param encoded: PBKDF2 hashed Password
    :return: algorithm, iterations, salt, hash
    """
    algorithm, iterations, salt, h = encoded.split('$', 3)
    return algorithm, iterations, salt, h


def generate_salt(length):
    """
    Generate a unique random Salt
    :return: unique random Salt
    """
    return ''.join(secrets.choice(alphabet) for _ in range(length))
