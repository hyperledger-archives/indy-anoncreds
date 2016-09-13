from _sha256 import sha256

import base58
from charm.toolbox.conversion import Conversion

from copy import copy

from charm.core.math.integer import randomPrime, random, integer, randomBits, \
    isPrime
from anoncreds.protocol.globals import LARGE_PRIME, LARGE_VPRIME_PRIME, LARGE_E_START, LARGE_E_END_RANGE, KEYS, \
    MASTER_SEC_RAND, PK_N, PK_S, PK_Z, PK_R, NAME, VERSION, TYPE, IP, PORT, TYPE_CL
from anoncreds.protocol.types import CredDefPublicKey, CredDefSecretKey, SerFmt
from anoncreds.protocol.utils import randomQR, get_prime_in_range, randomString, strToCharmInteger

primes = {
    "prime1":
        (integer(157329491389375793912190594961134932804032426403110797476730107804356484516061051345332763141806005838436304922612495876180233509449197495032194146432047460167589034147716097417880503952139805241591622353828629383332869425029086898452227895418829799945650973848983901459733426212735979668835984691928193677469),
            integer(151323892648373196579515752826519683836764873607632072057591837216698622729557534035138587276594156320800768525825023728398410073692081011811496168877166664537052088207068061172594879398773872352920912390983199416927388688319207946493810449203702100559271439586753256728900713990097168484829574000438573295723))
    , "prime2":
        (integer(150619677884468353208058156632953891431975271416620955614548039937246769610622017033385394658879484186852231469238992217246264205570458379437126692055331206248530723117202131739966737760399755490935589223401123762051823602343810554978803032803606907761937587101969193241921351011430750970746500680609001799529),
        integer(171590857568436644992359347719703764048501078398666061921719064395827496970696879481740311141148273607392657321103691543916274965279072000206208571551864201305434022165176563363954921183576230072812635744629337290242954699427160362586102068962285076213200828451838142959637006048439307273563604553818326766703))
    }


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

        self.p_prime = genPrime() if p_prime is None else primes.get(p_prime)[0] if isinstance(p_prime, str) else p_prime
        self.p = 2 * self.p_prime + 1

        self.q_prime = genPrime() if q_prime is None else primes.get(q_prime)[1] if isinstance(q_prime, str) else q_prime
        self.q = 2 * self.q_prime + 1

        n = self.p * self.q

        # Generate a random quadratic number
        S = randomQR(n)

        # Generate random numbers corresponding to every attributes
        Xz = self._genX()
        Xr = {}

        for name in attrNames:
            Xr[str(name)] = self._genX()

        # Generate `Z` as the exponentiation of the quadratic random 'S' .
        # over the random `Xz` in the group defined by modulus `n`
        Z = (S ** Xz) % n

        # Generate random numbers corresponding to every attributes
        R = {}
        for name in attrNames:
            R[str(name)] = (S ** Xr[str(name)]) % n
        # R["0"] is a random number needed corresponding to master secret
        R["0"] = (S ** self._genX()) % n

        self._pk = CredDefPublicKey(n, R, S, Z)
        self.sk = {'p': self.p, 'q': self.q}

    def _genX(self):
        X = 0
        upperValue = self.p_prime * self.q_prime - 1
        while X < 2:
            X = integer(random(upperValue))
        return X

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

    @staticmethod
    def getPk(keys):
        N = strToCharmInteger(base58decode(keys["N"]))
        S = strToCharmInteger(base58decode(keys["S"]))
        Z = strToCharmInteger(base58decode(keys["Z"]))
        R = {}
        for k, v in keys["R"].items():
            R[k] = strToCharmInteger(base58decode(v))
        return CredDefPublicKey(N, R, S, Z)

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

    @classmethod
    def getCryptoInteger(cls, val):
        return strToCharmInteger(val)

    def get(self, serFmt: SerFmt=SerFmt.default):
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

    @classmethod
    def getStaticPPrime(cls, key):
        return primes.get(key)[0]

    @classmethod
    def getStaticQPrime(cls, key):
        return primes.get(key)[1]

    @classmethod
    def getEncodedAttrs(cls, attrs):
        """
        This function will encode all the attributes to 256 bit integers

        :param attrs: The attributes to pass in credentials
        :return:
        """

        return {key: Conversion.bytes2integer(sha256(value.encode()).digest())
                for key, value in attrs.items()}


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
