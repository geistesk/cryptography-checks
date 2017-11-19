#!/usr/bin/env python

from rsa import RSA
from dh import DHUser, DHSession

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

    # Diffie-Hellman
    # CRYPTO-35
    dh_session = DHSession(353, 3)
    dh_user_a = DHUser(dh_session, 97)
    dh_user_b = DHUser(dh_session, 233)

    assert dh_user_a.y == 40
    assert dh_user_b.y == 248
    assert dh_session.session_key(dh_user_a, dh_user_b) == \
        dh_user_a.session_key(dh_user_b.public_key()) == \
        dh_user_b.session_key(dh_user_a.public_key()) == 160

    print('Succeeded.')
