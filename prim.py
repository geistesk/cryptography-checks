from fractions import gcd

'Inefficient prim-related functions'

def is_prim(n):
    'Checks if the given number is prim.'
    if n < 2:
        return False

    for i in range(2, n):
        if n % i == 0:
            return False
    return True

def prims_up_to(n):
    'Returns a list of all prim-numbers up to n.'
    return filter(is_prim, range(n))


def find_prims(n):
    'Tries to return a list of tuple of prims which product is n.'
    prims = prims_up_to(n)
    pairs = []

    for p in prims:
        for q in prims:
            if p * q == n and (p, q) not in pairs and (q, p) not in pairs:
                pairs += [(p, q)]
    return pairs


def is_primitive_root_mod(a, q):
    'Checks if a is a primitive rood mod q.'

    # https://stackoverflow.com/a/40190938
    def prim_roots(modulo):
        required_set = {num for num in range(1, modulo) if gcd(num, modulo)}
        return [g for g in range(1, modulo) if required_set == {pow(g, powers, modulo)
                for powers in range(1, modulo)}]

    return a in prim_roots(q)
