from charm.core.math.integer import randomPrime, random, integer, randomBits

from anoncreds.protocol.globals import lprime, lvprimeprime, lestart, leendrange
from anoncreds.protocol.models import IssuerPublicKey
from anoncreds.protocol.utils import randomQR, get_prime_in_range


class Issuer:
    def __init__(self, attrNames):
        """
        Setup an issuer
        :param attrNames: List of all attribute names
        """

        # Generate 2 large primes `p_prime` and `q_prime` and use them
        # to generate another 2 primes `p` and `q` of 1024 bits
        self.p_prime = randomPrime(lprime)
        self.p_prime = integer(157329491389375793912190594961134932804032426403110797476730107804356484516061051345332763141806005838436304922612495876180233509449197495032194146432047460167589034147716097417880503952139805241591622353828629383332869425029086898452227895418829799945650973848983901459733426212735979668835984691928193677469)
        # i = 0
        # while not isPrime(2 * self.p_prime + 1):
        #     self.p_prime = randomPrime(lprime)
        #     i += 1
        # print("Found prime in {} iteration".format(i))
        self.p = 2 * self.p_prime + 1

        # self.q_prime = randomPrime(lprime)
        self.q_prime = integer(151323892648373196579515752826519683836764873607632072057591837216698622729557534035138587276594156320800768525825023728398410073692081011811496168877166664537052088207068061172594879398773872352920912390983199416927388688319207946493810449203702100559271439586753256728900713990097168484829574000438573295723)
        # i = 0
        # while not isPrime(2 * self.q_prime + 1):
        #     self.q_prime = randomPrime(lprime)
        #     i += 1
        # print("Found prime in {} iteration".format(i))
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

        self._pk = IssuerPublicKey(n, R, S, Z)
        self.sk = {'p': self.p, 'q': self.q}

    @property
    def PK(self) -> IssuerPublicKey:
        """
        Generate key pair for the issuer
        :return: Tuple of public-secret key for the issuer
        """
        return self._pk

    def issue(self, u, attrs):
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

    def _sign(self, pk: IssuerPublicKey, attrs, v=0, u=0, e=0):
        N, R, S, Z, = pk
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
