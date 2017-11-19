from random import randint


class EGSession:
    'The EGSession stores q, a and is referenced by each EGUser.'

    def __init__(self, q, a):
        'Create a new EG-Session with given q, a.'
        self.q = q
        self.a = a


class EGUser:
    'An EGUser is a part of an EGSession.'

    def __init__(self, eg_session, x):
        self.eg_session = eg_session
        self.x = x
        self.y = pow(self.eg_session.a, self.x) % self.eg_session.q

        assert 1 < x < (self.eg_session.q - 1)

    def public_key(self):
        'Returns the public key y.'
        return self.y

    def private_key(self):
        'Returns the private key x.'
        return self.x

    def encrypt(self, recipient, m, k=None):
        'Encrypts the message m (number) for the recipient (EGUser).'
        assert 0 <= m <= (self.eg_session.q - 1)

        if k is None:
            k = randint(1, self.eg_session.q - 1)
        otk = pow(recipient.public_key(), k) % self.eg_session.q
        return (pow(self.eg_session.a, k) % self.eg_session.q,
                (otk * m) % self.eg_session.q)

    def decrypt(self, c):
        'Decrypts an encrypted message (pair).'
        # > computing M as M = C_2 * K^(-1) mod q
        # K^(-1) is not the K to the power of (-1), but the inverse
        # of K in the group G.
        tmp = pow(c[0], self.eg_session.a - self.private_key() - 1) * c[1]
        return tmp % self.eg_session.q
