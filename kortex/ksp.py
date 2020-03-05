# Copyright (c) 2020 Fluffy Koalas open source software. This file is licensed under the MIT license. #

from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.backends import default_backend
from kortex.utils import check_type
from kortex.exceptions import InvalidToken


__all__ = ['KSP1']


class KSP1:
    """
    Implementation of Koala Security Protocol 1. Please see the SPECS.rst file in the repo for details.
    """
    def __init__(self, key, nonce, mac_key):
        check_type(bytes, key=key, nonce=nonce, mac_key=mac_key)
        
        if len(key) not in (16, 32):
            raise ValueError('invalid length for key. must be 128 or 256 bits.')
        if len(nonce) != 16:
            raise ValueError('invalid length for nonce. must be 128 bits')
        if len(mac_key) != 16:
            raise ValueError('invalid length for mac_key. must be 128 bits.')
        
        self._key = key
        self._nonce = nonce
        self._mac_key = mac_key
    
    def encryptor(self):
        return _KSP1_encryptor(self._key, self._nonce, self._mac_key)
    
    def decryptor(self):
        return _KSP1_decryptor(self._key, self._nonce, self._mac_key)


class _KSP1_encryptor:
    """
    DO NOT CALL
    
    Use KSP1().encryptor() instead
    """
    
    def __init__(self, key, nonce, mac_key):
        self._aes = Cipher(algorithms.AES(key), modes.CTR(nonce), default_backend()).encryptor()
        self._mac = CMAC(algorithms.AES(mac_key), default_backend())
    
    def update(self, data):
        data = self._aes.update(data)
        self._mac.update(data)
        return data
    
    def finalize(self):
        return self._mac.finalize()
    

class _KSP1_decryptor:
    """
    DO NOT CALL
    
    Use KSP1().decryptor() instead
    """
    
    def __init__(self, key, nonce, mac_key):
        self._aes = Cipher(algorithms.AES(key), modes.CTR(nonce), default_backend()).decryptor()
        self._mac = CMAC(algorithms.AES(mac_key), default_backend())
    
    def update(self, data):
        self._mac.update(data)
        return self._aes.update(data)
    
    def finalize(self, tag):
        try:
            self._mac.verify(tag)
        except Exception:
            raise InvalidToken
