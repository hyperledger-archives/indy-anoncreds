from charm.core.math.integer import randomPrime, random, integer, randomBits, \
    isPrime

from anoncreds.protocol.globals import lprime, lvprimeprime, lestart, leendrange
from anoncreds.protocol.utils import randomQR, get_prime_in_range, randomString


class CredentialDefinition:
    def __init__(self,
                 attrNames,
                 name=None, version=None,
                 p_prime=None, q_prime=None):
        """
        Setup an issuer
        :param attrNames: List of all attribute names
        """

        self.name = name or randomString(6)
        self.version = version or "1.0"

        if not attrNames and isinstance(attrNames, list):
            raise ValueError("List of attribute names is required to setup credential definition")

        def genPrime():
            # Generate 2 large primes `p_prime` and `q_prime` and use them
            # to generate another 2 primes `p` and `q` of 1024 bits
            prime = randomPrime(lprime)
            i = 0
            while not isPrime(2 * prime + 1):
                prime = randomPrime(lprime)
                i += 1
            print("In {} iterations, found prime {}".format(i, prime))
            return prime

        self.p_prime = p_prime or genPrime()
        self.p = 2 * self.p_prime + 1

        self.q_prime = q_prime or genPrime()
        self.q = 2 * self.q_prime + 1

        n = self.p * self.q

        # Generate a random quadratic number
        S = randomQR(n)

        # Generate random numbers corresponding to every attributes
        Xz = integer(random(n))
        Xr = {}

        for name in attrNames:
            Xr[str(name)] = integer(random(n))

        # Generate `Z` as the exponentiation of the quadratic random 'S' .
        # over the random `Xz` in the group defined by modulus `n`
        Z = (S ** Xz) % n

        # Generate random numbers corresponding to every attributes
        R = {}
        for name in attrNames:
            R[str(name)] = S ** Xr[str(name)]
        # R["0"] is a random number needed corresponding to master secret
        R["0"] = S ** integer(random(n))

        self._pk = {'N': n, 'S': S, 'Z': Z, 'R': R}
        self.sk = {'p': self.p, 'q': self.q}

    @property
    def PK(self):
        """
        Generate key pair for the issuer
        :return: Tuple of public-secret key for the issuer
        """
        return self._pk

    def generateCredential(self, u, attrs):
        """
        Issue the credential for the defined attributes
        :param u: The `u` value provided by the prover
        :param attrs: The attributes for which the credential needs to be generated
        :return: The presentation token as a combination of (A, e, vprimeprime)
        """
        # Generate a random prime and
        # Set the Most-significant-bit to 1
        vprimeprime = integer(randomBits(lvprimeprime) |
                              (2 ** (lvprimeprime - 1)))

        # Generate prime number in the range (2^596, 2^596 + 2^119)
        estart = 2 ** lestart
        eend = (estart + 2 ** leendrange)

        e = get_prime_in_range(estart, eend)

        A = self._sign(self._pk, attrs, vprimeprime, u, e)
        return A, e, vprimeprime

    def _sign(self, pk, attrs, v, u, e):
        R = pk["R"]
        Z = pk["Z"]
        S = pk["S"]
        N = pk["N"]
        Rx = 1 % N

        # Get the product sequence for the (R[i] and attrs[i]) combination
        for k, val in attrs.items():
            Rx = Rx * (R[str(k)] ** val)

        if u != 0:
            u = u % N
            Rx *= u

        nprime = self.p_prime * self.q_prime
        einverse = e % nprime

        Q = Z / (Rx * (S ** v)) % N
        A = Q ** (einverse ** -1) % N

        return A
