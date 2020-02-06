# Copyright (c) 2020 Fluffy Koalas open source software. This file is licensed under the MIT license. #
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def scrypt(password, salt, length, n=2**16, r=8, p=1):
    return Scrypt(salt, length, n, r, p, default_backend()).derive(password)
