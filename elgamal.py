from fractions import gcd
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
        # K^(-1) is not the K to the power of (-1), but the inverse
        # of K in the group G.
        tmp = pow(c[0], self.eg_session.a - self.private_key() - 1) * c[1]
        return tmp % self.eg_session.q

    def sign(self, m, k, k_inv):
        'This EGUser creates a signature with given hash `m` and random `k`.'
        assert 0 <= m <= (self.eg_session.q - 1)
        assert 1 <= k <= (self.eg_session.q - 1)
        assert gcd(k, self.eg_session.q - 1) == 1

        s1 = pow(self.eg_session.a, k) % self.eg_session.q
        s2 = (k_inv * (m - self.private_key() * s1)) % (self.eg_session.q - 1)

        return (s1, s2)

    def verify(self, sender, s1, s2, m):
        'Another EGUser in the same EGSession checks the sender\'s signature.'
        v1 = pow(self.eg_session.a, m) % self.eg_session.q
        v2 = (pow(sender.public_key(), s1) * pow(s1, s2)) % self.eg_session.q
        return v1 == v2
