from prim import is_prim, is_primitive_root_mod


class DHSession:
    'The DHSession stores q, a and is referenced by each DHUser.'

    def __init__(self, q, a):
        'Create a new DH-Session with given q, a.'
        self.q = q
        self.a = a

        assert is_prim(self.q)
        assert is_primitive_root_mod(self.a, self.q)

    def session_key(self, a, b):
        'Create a shared session key for two DHUsers a and b.'
        return pow(self.a, a.private_key() * b.private_key()) % self.q


class DHUser:
    'A DHUser is part of a DHSession.'

    def __init__(self, dh_session, x):
        'Create a new DHUser within a DHSession and a secrete key (number) x.'
        self.dh_session = dh_session
        self.x = x
        self.y = pow(self.dh_session.a, self.x) % self.dh_session.q

        assert self.x < self.dh_session.q

    def public_key(self):
        'Returns the public key y.'
        return self.y

    def private_key(self):
        'Returns the private key x.'
        return self.x

    def session_key(self, public_key):
        'Creates a shared session key for another DHUser\'s public key.'
        return pow(public_key, self.private_key()) % self.dh_session.q
