#!/usr/bin/env python

from rsa import RSA

if __name__ == '__main__':
    # RSA
    # CRYPTO-19
    c19 = RSA(17, 11, 7)
    assert c19._d == 23
    assert c19.public_key() == (7, 187)
    assert c19.private_key() == (23, 187)

    # CRYPTO-20
    c = RSA.encrypt(c19.public_key(), 88)
    m = RSA.decrypt(c19.private_key(), c)
    assert c == 11
    assert m == 88



    print('Succeeded.')
