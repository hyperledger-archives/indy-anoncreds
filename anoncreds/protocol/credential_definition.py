import base58

from copy import copy

from charm.core.math.integer import randomPrime, random, integer, randomBits, \
    isPrime
from anoncreds.protocol.globals import LARGE_PRIME, LARGE_VPRIME_PRIME, LARGE_E_START, LARGE_E_END_RANGE, KEYS, \
    MASTER_SEC_RAND, PK_N, PK_S, PK_Z, PK_R, NAME, VERSION, TYPE, IP, PORT, TYPE_CL
from anoncreds.protocol.types import CredDefPublicKey, CredDefSecretKey, SerFmt
from anoncreds.protocol.utils import randomQR, get_prime_in_range, randomString

static_p_prime=integer(157329491389375793912190594961134932804032426403110797476730107804356484516061051345332763141806005838436304922612495876180233509449197495032194146432047460167589034147716097417880503952139805241591622353828629383332869425029086898452227895418829799945650973848983901459733426212735979668835984691928193677469)
static_q_prime=integer(151323892648373196579515752826519683836764873607632072057591837216698622729557534035138587276594156320800768525825023728398410073692081011811496168877166664537052088207068061172594879398773872352920912390983199416927388688319207946493810449203702100559271439586753256728900713990097168484829574000438573295723)


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

        self._name = name or randomString(6)
        self._version = version or "1.0"
        self.ip = ip
        self.port = port
        self.attrNames = attrNames

        if not attrNames and isinstance(attrNames, list):
            raise ValueError("List of attribute names is required to "
                             "setup credential definition")

        self.p_prime = static_p_prime if str(p_prime) == "static" else genPrime()
        self.p = 2 * self.p_prime + 1

        self.q_prime = static_q_prime if str(q_prime) == "static" else genPrime()
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

        self._pk = CredDefPublicKey(n, R, S, Z)
        self.sk = {'p': self.p, 'q': self.q}

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def version(self) -> str:
        return self._version

    @version.setter
    def version(self, version):
        self._version = version

    @property
    def PK(self) -> CredDefPublicKey:
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

    def get(self, serFmt: SerFmt=SerFmt.charmInteger):
        pk = copy(self.PK)
        R = copy(pk.R)
        data = {
            NAME: self.name,
            VERSION: self.version,
            TYPE: TYPE_CL,
            IP: self.ip,
            PORT: self.port,
            KEYS: {
                MASTER_SEC_RAND: R["0"],
                PK_N: pk.N,
                PK_S: pk.S,
                PK_Z: pk.Z,
                PK_R: R  # TODO Master secret rand number, R[0] is still passed,
                #  remove that
            }
        }
        serFuncs = {
            serFmt.py3Int: int,
            serFmt.default: integer,
            serFmt.base58: base58encode,
        }
        return serialize(data, serFuncs[serFmt])


def genPrime():
    # Generate 2 large primes `p_prime` and `q_prime` and use them
    # to generate another 2 primes `p` and `q` of 1024 bits
    prime = randomPrime(LARGE_PRIME)
    i = 0
    while not isPrime(2 * prime + 1):
        prime = randomPrime(LARGE_PRIME)
        i += 1
    print("In {} iterations, found prime {}".format(i, prime))
    return prime


def getDeserializedSK(serializedSK) -> CredDefSecretKey:
    p, q = serializedSK.split(",")
    return CredDefSecretKey(integer(int(p)), integer(int(q)))


def getPPrime(sk: CredDefSecretKey):
    return (sk.p - 1) / 2


def getQPrime(sk: CredDefSecretKey):
    return (sk.q - 1) / 2


def generateCredential(u, attrs, pk, p_prime, q_prime):
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
    vprimeprime = integer(randomBits(LARGE_VPRIME_PRIME) |
                          (2 ** (LARGE_VPRIME_PRIME - 1)))
    # Generate prime number in the range (2^596, 2^596 + 2^119)
    estart = 2 ** LARGE_E_START
    eend = (estart + 2 ** LARGE_E_END_RANGE)
    e = get_prime_in_range(estart, eend)
    A = _sign(pk, attrs, vprimeprime, u, e, p_prime, q_prime)
    return A, e, vprimeprime


def _sign(pk, attrs, v, u, e, p_prime, q_prime):
    Rx = 1 % pk.N
    # Get the product sequence for the (R[i] and attrs[i]) combination
    for k, val in attrs.items():
        Rx = Rx * (pk.R[str(k)] ** val)
    if u != 0:
        u = u % pk.N
        Rx *= u
    nprime = p_prime * q_prime
    einverse = e % nprime
    Q = pk.Z / (Rx * (pk.S ** v)) % pk.N
    A = Q ** (einverse ** -1) % pk.N
    return A

def serialize(data, serfunc):
    for k, v in data[KEYS].items():
        if isinstance(v, integer):
            # int casting works with Python 3 only.
            # for Python 2, charm's serialization api must be used.
            data[KEYS][k] = serfunc(v)
        if k == PK_R :
            data[KEYS][k] = {key: serfunc(val) for key, val in v.items()}
    return data


def base58encode(i):
    return base58.b58encode(str(i).encode())


def base58decode(i):
    return base58.b58decode(str(i)).decode()


def base58decodedInt(i):
    # TODO: DO exception handling
    return int(base58.b58decode(str(i)).decode())
