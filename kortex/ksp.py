# Copyright (c) 2020 Fluffy Koalas open source software. This file is licensed under the MIT license. #

from Cryptodome.Cipher import AES
from Cryptodome.Hash.CMAC import new as _cmac_new
from kortex.utils import _check_type


__all__ = ['KSP_1']


class KSP_1:
    """
    Implementation of Koala Security Protocol 1. Please see the SPECS.rst file in the repo for details.
    """
    def __init__(self, key, nonce, mac_key):
        _check_type(bytes, key=key, nonce=nonce, mac_key=mac_key)
        
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
    """
    
    def __init__(self, key, nonce, mac_key):
        self._aes = AES.new(key, AES.MODE_CTR, initial_value=nonce, nonce=b'')
        self._mac = _cmac_new(mac_key, ciphermod=AES)
    
    def update(self, data):
        data = self._aes.encrypt(data)
        self._mac.update(data)
        return data
    
    def finalize(self):
        return self._mac.digest()
    

class _KSP1_decryptor:
    """
    DO NOT CALL
    """
    
    def __init__(self, key, nonce, mac_key):
        self._aes = AES.new(key, AES.MODE_CTR, initial_value=nonce, nonce=b'')
        self._mac = _cmac_new(mac_key, ciphermod=AES)
    
    def update(self, data):
        self._mac.update(data)
        return self._aes.decrypt(data)
    
    def finalize(self, tag):
        self._mac.verify(tag)
