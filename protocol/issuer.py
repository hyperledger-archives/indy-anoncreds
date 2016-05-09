from charm.core.math.integer import randomPrime, random, integer, randomBits
from protocol.globals import lprime, lvprimeprime, le
from protocol.utils import randomQR

class Issuer:
    def __init__(self, l):
        """
        Setup an issuer
        :param l: Number of attributes
        """
        randPPrime = randomPrime(lprime)
        self.p = integer(2 * randPPrime + 1)

        randQPrime = randomPrime(lprime)
        self.q = integer(2 * randQPrime + 1)

        n = self.p * self.q
        nprime = randPPrime * randQPrime

        S = randomQR(n)
        # AS: Not sure where we would need this
        self.randomQuadResidue = S % n

        Xz = integer(random(nprime))
        Xr = {}

        for i in range(1, l+1):
            Xr[str(i)] = integer(random(nprime))

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
        vprimeprime = randomBits(lvprimeprime)
        e = randomPrime(le)

        sig = self.__sign__(self.pk, self.sk, attrs, vprimeprime, u, e)
        return sig["A"], e, vprimeprime

    def __sign__(self, pk, sk, attr, v=0, u=0, e=0):
        R = pk["R"]
        Z = pk["Z"]
        S = pk["S"]
        N = pk["N"]
        Rx = 1 % N

        # print(R)
        # print(list(attr.values()))
        # attr_values = list(attr.values())
        # for index in attr_values:
        #     Rx = Rx * (R[index + 1] ** attr_values[index])

        for i in range(1, len(attr) + 1):
            Rx = Rx * (R[str(i)] ** attr[str(i)])

        if u != 0:
            u = u % N
            Rx = Rx * u

        eprime = (sk["p"] - 1) * (sk["q"] - 1)
        eprime = e % eprime

        Q = Z / (Rx * (S ** v)) % N
        A = Q ** (eprime ** -1) % N  # This part is unclear. Revisit it

        return {'A': A, 'Q': Q, 'e': e, 'v': v}


