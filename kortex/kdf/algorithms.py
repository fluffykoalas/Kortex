# Copyright (c) 2020 Fluffy Koalas open source software. This file is licensed under the MIT license. #
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from ..exceptions import SecurityRiskError

__all__ = ['scrypt', 'derive']


def scrypt(password: bytes, salt: bytes, length: int, n=2**16, r=8, p=1):
    """
    
    :param password: the password to derive a key from
    :param salt: the salt to randomise the password. Use os.urandom wherever possible.
    :param length: the length of the derived key
    :param n:
    :param r:
    :param p: parallelization factor. Recommended value 1
    :return: a derived key of length 'length'
    :rtype: bytes
    """
    
    if len(salt) != 16:
        raise SecurityRiskError('your salt must be 16 bytes long')
    if n < 2**14:
        raise SecurityRiskError('n is too small')
    if r < 8:
        raise SecurityRiskError('r is too small')
    
    return Scrypt(salt, length, n, r, p, default_backend()).derive(password)


derive = scrypt
