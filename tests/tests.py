# Copyright (c) 2020 Fluffy Koalas open source software. This file is licensed under the MIT license. #

from kortex import kdf, ksp, utils, exceptions
import unittest
import os


# ------------------------------- VECTORS -------------------------------------
scrypt_vectors = [
        {
            "password": "a08b4f79",
            "salt": "62613434336238313764613631636536",
            "n": 16384,
            "r": 8,
            "p": 1,
            "expected": "34005bb40231b0992078dc51e4683cf9"
        },
        {
            "password": "48f69222",
            "salt": "36356331636236653834663262323663",
            "n": 32768,
            "r": 8,
            "p": 1,
            "expected": "c9f78106c7cca73711edbc54ac1d429f"
        },
        {
            "password": "30d42336",
            "salt": "38623166646537613464323466326161",
            "n": 65536,
            "r": 8,
            "p": 1,
            "expected": "45f643d304c7f21005bb698d5ac8250c"
        },
        {
            "password": "e61041e2",
            "salt": "36306338303838373261353833343131",
            "n": 131072,
            "r": 8,
            "p": 1,
            "expected": "371dd814edfc9d312a33c81a031ffa47"
        },
        {
            "password": "54fe8dfc",
            "salt": "33646632313631366565613933343462",
            "n": 262144,
            "r": 8,
            "p": 1,
            "expected": "7a0fa88a1755e2c8698cbe8fc9a3e4bc"
        },
        {
            "password": "070c4430",
            "salt": "63333638653362333032316364363861",
            "n": 524288,
            "r": 8,
            "p": 1,
            "expected": "4ada6e4e17418b98d76b5cf2e980f126"
        }
    ]
# -----------------------------------------------------------------------------


# ------------------------------- TESTS ---------------------------------------
class TestKortexKDF(unittest.TestCase):
    
    def test_scrypt(self):
        for case in scrypt_vectors:
            password = bytes.fromhex(case['password'])
            salt = bytes.fromhex(case['salt'])
            n = case['n']
            r = case['r']
            p = case['p']
            expected_val = bytes.fromhex(case['expected'])
            
            key = kdf.derive(password, salt, len(expected_val), n, r, p)
            
            self.assertEqual(key, expected_val, 'scrypt test failed')


class TestKoalaSecurityProtocols(unittest.TestCase):
    
    def test_ksp1(self):
        for i in range(2):
            key, nonce, mac_key = [os.urandom(16) for _ in range(3)]
            
            cipher = ksp.KSP1(key, nonce, mac_key)
            plaintext = b'The quick planet runs circles around the lazy star'
            
            # Encrypt
            encryptor = cipher.encryptor()
            ctext = encryptor.update(plaintext)
            tag = encryptor.finalize()
            
            # Decrypt
            decryptor = cipher.decryptor()
            ptext = decryptor.update(ctext)
            
            try:
                decryptor.finalize(tag)
            except exceptions.InvalidToken:
                self.fail('Verification failed. Please submit a bug report at github.com/fluffykoalas/kortex')
            
            self.assertEqual(ptext, plaintext)


class TestUtils(unittest.TestCase):
    
    def test_type_check_pass(self):
        
        try:
            utils.check_type(
                str,
                stringval1='string',
                stringval2='another string',
                still_a_string='still a string'
            )
        except TypeError:
            self.fail('utils.check_type raised unexpected TypeError')
        
    def test_type_check_fail(self):
        
        with self.assertRaises(TypeError):
            utils.check_type(
                bytes,
                notbytes='this is a string not a byte string',
                alsonotbytes=123456789
            )
