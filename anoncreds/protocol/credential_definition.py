import base58

from copy import copy

from charm.core.math.integer import randomPrime, random, integer, randomBits, \
    isPrime

from functools import singledispatch
from anoncreds.protocol.globals import lprime, lvprimeprime, lestart, leendrange
from anoncreds.protocol.types import IssuerPublicKey, CredDefSecretKey, SerFmt
from anoncreds.protocol.utils import randomQR, get_prime_in_range, randomString


class CredentialDefinition:
    def __init__(self,
                 attrNames,
                 name=None, version=None,
                 p_prime=None, q_prime=None,
                 ip=None, port=None):
        """
        Setup an issuer

        :param attrNames: List of all attribute names
        """

        self.name = name or randomString(6)
        self.version = version or "1.0"
        self.ip = ip
        self.port = port
        self.attrNames = attrNames

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

        self._pk = IssuerPublicKey(n, R, S, Z)
        self.sk = {'p': self.p, 'q': self.q}

    @property
    def PK(self) -> IssuerPublicKey:
        """
        Generate public key of credential definition

        :return: Public key for the credential definition
        """
        return self._pk

    @property
    def SK(self) -> CredDefSecretKey:
        """
        Generate secret key of credential definition

        :return: Secret key for the credential definition
        """
        return CredDefSecretKey(**self.sk)

    @property
    def serializedSK(self) -> str:
        return "{},{}".format(int(self.p), int(self.q))

    @classmethod
    def getDeserializedSK(cls, serializedSK) -> CredDefSecretKey:
        p, q = serializedSK.split(",")
        return CredDefSecretKey(integer(int(p)), integer(int(q)))

    @classmethod
    def getPPrime(cls, sk: CredDefSecretKey):
        return (sk.p - 1) / 2

    @classmethod
    def getQPrime(cls, sk: CredDefSecretKey):
        return (sk.q - 1) / 2

    @classmethod
    def generateCredential(cls, u, attrs, pk, p_prime, q_prime):
        """
        Issue the credential for the defined attributes

        :param u: The `u` value provided by the prover
        :param attrs: The attributes for which the credential needs to be generated
        :return: The presentation token as a combination of (A, e, vprimeprime)
        """
        if not u:
            raise ValueError("u must be provided to issue a credential")
        # Generate a random prime and
        # Set the Most-significant-bit to 1
        vprimeprime = integer(randomBits(lvprimeprime) |
                              (2 ** (lvprimeprime - 1)))
        # Generate prime number in the range (2^596, 2^596 + 2^119)
        estart = 2 ** lestart
        eend = (estart + 2 ** leendrange)
        e = get_prime_in_range(estart, eend)
        A = cls._sign(pk, attrs, vprimeprime, u, e, p_prime, q_prime)
        return A, e, vprimeprime

    @classmethod
    def _sign(cls, pk, attrs, v, u, e, p_prime, q_prime):
        N, R, S, Z = pk
        Rx = 1 % N
        # Get the product sequence for the (R[i] and attrs[i]) combination
        for k, val in attrs.items():
            Rx = Rx * (R[str(k)] ** val)
        if u != 0:
            u = u % N
            Rx *= u
        nprime = p_prime * q_prime
        einverse = e % nprime
        Q = Z / (Rx * (S ** v)) % N
        A = Q ** (einverse ** -1) % N
        return A

    def get(self, serFmt: SerFmt=SerFmt.charmInteger):
        pk = copy(self.PK)
        R = copy(pk.R)
        data = {
            "name": self.name,
            "version": self.version,
            "type": "CL",
            "ip": self.ip,
            "port": self.port,
            "keys": {
                "master_secret_rand": R["0"],
                "N": pk.N,
                "S": pk.S,
                "Z": pk.Z,
                "R": R  # TODO Master secret rand number, R[0] is still passed,
                #  remove that
            }
        }
        serFuncs = {
            serFmt.py3Int: int,
            serFmt.charmInteger: integer,
            serFmt.base58: base58encode,
        }
        return serialize(data, serFuncs[serFmt])


def serialize(data, serfunc):
    for k, v in data['keys'].items():
        if isinstance(v, integer):
            # int casting works with Python 3 only.
            # for Python 2, charm's serialization api must be used.
            data['keys'][k] = serfunc(v)
        if k == 'R':
            data['keys'][k] = {key: serfunc(val) for key, val in v.items()}
    return data


def base58encode(i):
    return base58.b58encode(str(i).encode())

