from random import randint
from charm.core.math.integer import randomPrime, random, integer, randomBits, isPrime
from protocol.globals import lprime, lvprimeprime, le
from protocol.utils import randomQR

class Issuer:
    def __init__(self, l):
        """
        Setup an issuer
        :param l: Number of attributes
        """
        self.p_prime = randomPrime(lprime)
        while not isPrime(2 * self.p_prime + 1):
            self.p_prime = randomPrime(lprime)
        self.p = 2 * self.p_prime + 1

        self.q_prime = randomPrime(lprime)
        while not isPrime(2 * self.q_prime + 1):
            self.q_prime = randomPrime(lprime)
        self.q = 2 * self.q_prime + 1

        n = self.p * self.q

        S = randomQR(n)
        # AS: Not sure where we would need this
        self.randomQuadResidue = S % n

        Xz = integer(random(n))
        Xr = {}

        for i in range(1, l+1):
            Xr[str(i)] = integer(random(n))

        Z = (S ** Xz) % n

        R = {}
        for i in range(1, l+1):
            R[str(i)] = S ** Xr[str(i)]

        self.pk = {'N': n, 'S': S, 'Z': Z, 'R': R}
        self.sk = {'p': self.p, 'q': self.q}

    def gen_key_pair(self):
        """
        Generate key pair for the issuer
        :return: Tuple of public-secret key for the issuer
        """
        return self.pk, self.sk

    def issuance(self, u, attrs):
        # Set the Most-significant-bit to 1
        vprimeprime = integer(randomBits(lvprimeprime) | (2 ** (lvprimeprime - 1)))

        estart = 2 ** 596
        eend = (estart + 2 ** 196)

        e = self.__get_prime_in_range(estart, eend)
        # e = randomPrime(le)

        sig = self.__sign__(self.pk, attrs, vprimeprime, u, e)
        return sig["A"], e, vprimeprime

    def __sign__(self, pk, attr, v=0, u=0, e=0):
        R = pk["R"]
        Z = pk["Z"]
        S = pk["S"]
        N = pk["N"]
        Rx = 1 % N

        for i in range(1, len(attr) + 1):
            Rx = Rx * (R[str(i)] ** attr[str(i)])

        if u != 0:
            u = u % N
            Rx = Rx * u

        nprime = (self.p_prime * self.q_prime)
        e1 = e % nprime

        Q = Z / (Rx * (S ** v)) % N
        A = Q ** (e1 ** -1) % N  # This part is unclear. Revisit it

        return {'A': A, 'Q': Q, 'e': e, 'v': v}


    def __get_prime_in_range(self, start, end):
        n = 0
        while n < 100000:
            r = randint(start, end)
            if isPrime(r):
                # print("Found prime in {} iteration between {} and {}".format(n, start, end))
                return r
            n += 1
        raise Exception("Cannot find prime in 1000 iterations")
