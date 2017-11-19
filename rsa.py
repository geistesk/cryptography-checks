from fractions import gcd
from random import choice


class RSA:
    def __init__(self, p, q, e=None):
        'Generate a RSA-keypair with a given p, q and optinal e.'
        self.p = p
        self.q = q

        self._n = p * q
        self._phi = RSA.phi(p, q)
        self._e = e if e is not None else RSA.select_e(self._phi)
        self._d = RSA.determine_d(self._e, self._phi)

        assert self._check_e()

    def _check_e(self):
        'Checks if the given e is valid. Will be called from __init__'
        return (1 < self._e < self._phi) and (gcd(self._e, self._phi) == 1)

    def public_key(self):
        'Returns the public key-tuple.'
        return (self._e, self._n)

    def private_key(self):
        'Returns the private key-tuple.'
        return (self._d, self._n)

    @staticmethod
    def encrypt(public_key, m):
        'Encrypts the message m (a number) for the given public key (e, n).'
        assert 0 <= m <= public_key[1]
        return pow(m, public_key[0]) % public_key[1]

    @staticmethod
    def decrypt(private_key, c):
        'Decrypts the message c (a number) with the given private key (d, n).'
        return pow(c, private_key[0]) % private_key[1]

    @staticmethod
    def phi(p, q):
        'Calculates the phi-function for n (by given p, q)'
        return (p - 1) * (q - 1)

    @staticmethod
    def find_possible_e(phi):
        'Returns a list of all possible e-values for given phi.'
        es = []
        for e in range(2, phi):
            if gcd(e, phi) == 1:
                es += [e]
        return es

    @staticmethod
    def select_e(phi):
        'Selects a pseudo-random e for given phi.'
        return choice(RSA.find_possible_e(phi))

    @staticmethod
    def determine_d(e, phi):
        'Determines a d for given e and phi.'
        for d in range(1, phi):
            if ((e * d) % phi) == 1:
                return d
        return None
