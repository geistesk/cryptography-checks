#!/usr/bin/env python

from rsa import RSA
from dh import DHUser, DHSession
from elgamal import EGUser, EGSession

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

    # ElGamal
    # CRYPTO-41
    eg_session = EGSession(19, 10)
    eg_user_a = EGUser(eg_session, 5)
    eg_user_b = EGUser(eg_session, 3)  # Bob's private key doesn't matter
    assert eg_user_a.y == 3

    (c1, c2) = eg_user_b.encrypt(eg_user_a, 17, k=6)
    assert (c1, c2) == (11, 5)
    assert eg_user_a.decrypt((c1, c2)) == 17

    # CRYPTO-89
    eg_session = EGSession(19, 10)
    eg_user_a = EGUser(eg_session, 16)
    eg_user_b = EGUser(eg_session, 3)  # Bob's private key doesn't matter
    assert eg_user_a.y == 4

    (s1, s2) = eg_user_a.sign(14, 5, 11)
    assert (s1, s2) == (3, 4)
    assert eg_user_b.verify(eg_user_a, s1, s2, 14)

    print('Succeeded.')
