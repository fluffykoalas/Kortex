# Copyright (c) 2020 Fluffy Koalas open source software. This file is licensed under the MIT license.

from .algorithms import scrypt as _scrypt

__all__ = ['derive']


def derive(password: bytes, salt: bytes, length: int, n=2**16, r=8, p=1):
    return _scrypt(password, salt, length, n, r, p)


def ksp1_quantum(password: bytes, salt: bytes, keysize: int):
    
    if keysize not in (16, 32):
        raise ValueError('Invalid keysize. Must be 16 or 32')
    val = _scrypt(password, salt, keysize+32, n=2**16, r=8, p=1)
    return [val[:16], val[16:32], val[32:]]
