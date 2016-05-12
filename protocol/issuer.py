from charm.core.math.integer import randomPrime, random, integer, randomBits, \
    isPrime
from protocol.globals import lprime, lvprimeprime, lestart, leendrange
from protocol.utils import randomQR, get_prime_in_range


class Issuer:
    def __init__(self, l):
        """
        Setup an issuer
        :param l: Number of attributes
        """
        self.p_prime = randomPrime(lprime)
        i = 0
        while not isPrime(2 * self.p_prime + 1):
            self.p_prime = randomPrime(lprime)
            i += 1
        print("Found prime in {} iteration".format(i))
        self.p = 2 * self.p_prime + 1

        self.q_prime = randomPrime(lprime)
        i = 0
        while not isPrime(2 * self.q_prime + 1):
            self.q_prime = randomPrime(lprime)
            i += 1
        print("Found prime in {} iteration".format(i))
        self.q = 2 * self.q_prime + 1

        n = self.p * self.q

        S = randomQR(n)
        # TODO: AS: Not sure where we would need this
        self.randomQuadResidue = S % n

        Xz = integer(random(n))
        Xr = {}

        for i in range(1, l+1):
            Xr[str(i)] = integer(random(n))

        Z = (S ** Xz) % n

        R = {}
        for i in range(1, l+1):
            R[str(i)] = S ** Xr[str(i)]

        self._pk = {'N': n, 'S': S, 'Z': Z, 'R': R}
        self.sk = {'p': self.p, 'q': self.q}

    @property
    def PK(self):
        """
        Generate key pair for the issuer
        :return: Tuple of public-secret key for the issuer
        """
        return self._pk

    def issuance(self, u, attrs):
        # Set the Most-significant-bit to 1
        vprimeprime = integer(randomBits(lvprimeprime) |
                              (2 ** (lvprimeprime - 1)))

        estart = 2 ** lestart
        eend = (estart + 2 ** leendrange)

        e = get_prime_in_range(estart, eend)

        sig = self._sign(self._pk, attrs, vprimeprime, u, e)
        return sig["A"], e, vprimeprime

    def _sign(self, pk, attr, v=0, u=0, e=0):
        R = pk["R"]
        Z = pk["Z"]
        S = pk["S"]
        N = pk["N"]
        Rx = 1 % N

        for i in range(1, len(attr) + 1):
            Rx = Rx * (R[str(i)] ** attr[str(i)])

        if u != 0:
            u = u % N
            Rx *= u

        nprime = self.p_prime * self.q_prime
        e1 = e % nprime

        Q = Z / (Rx * (S ** v)) % N
        A = Q ** (e1 ** -1) % N  # This part is unclear. Revisit it

        return {'A': A, 'Q': Q, 'e': e, 'v': v}
