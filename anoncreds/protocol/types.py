from collections import namedtuple
from enum import Enum
from hashlib import sha256
from typing import TypeVar, Sequence

from charm.core.math.integer import integer
from charm.toolbox.conversion import Conversion

from anoncreds.protocol.globals import APRIME, EVECT, MVECT, VVECT, C_VALUE, ETILDE, MTILDE, VTILDE, EPRIME, VPRIME, \
    CRED_A, CRED_E, CRED_V


class AttribType:
    def __init__(self, name: str, encode: bool):
        self.name = name
        self.encode = encode


class AttribDef:
    def __init__(self, name, attrTypes):
        if isinstance(name, str):
            self.names = [name]
            self.attrTypes = [attrTypes]
        else:
            self.names = name
            self.attrTypes = attrTypes

    @property
    def name(self):
        return ', '.join(self.names)

    def __getattr__(self, item):
        for attr_types in self.attrTypes:
            for at in attr_types:
                if item == at.name:
                    return at
            raise AttributeError

    def __add__(self, other):
        return AttribDef(self.names + other.names,
                         self.attrTypes + other.attrTypes)

    def attribs(self, **vals):
        return Attribs(self, **vals)

    def attribNames(self):
        return [at.name
                for attr_types in self.attrTypes
                for at in attr_types]


class Attribs:
    def __init__(self, credType: AttribDef, **vals):
        self.credType = credType
        self._vals = vals

    def encoded(self):
        """
        This function will encode all the attributes to 256 bit integers

        :param attrs: The attributes to pass in credentials
        :return:
        """

        named = {}
        for i in range(len(self.credType.names)):
            name = self.credType.names[i]
            attr_types = self.credType.attrTypes[i]
            encoded = {}
            for at in attr_types:
                if at.encode:
                    encoded[at.name] = Conversion.bytes2integer(
                        sha256(str(self._vals[at.name]).encode()).digest())
                else:
                    encoded[at.name] = self._vals[at.name]
            named[name] = encoded
        return named

    def __add__(self, other):
        vals = self._vals.copy()
        vals.update(other._vals)
        return Attribs(self.credType + other.credType, **vals)

    def __iter__(self):
        return self._vals.__iter__()

    def keys(self):
        return self._vals.keys()

    def values(self):
        return self._vals.values()

    def items(self):
        return self._vals.items()

class PublicParams:
    def __init__(self, Gamma, rho, g, h):
        self.Gamma = Gamma
        self.rho = rho
        self.g = g
        self.h = h

class CredDefId:
    def __init__(self, name=None, version=None, attrNames: Sequence[str]=None):
        self.name = name
        self.version = version
        self.attrNames = attrNames


class CredDefPublicKey:
    def __init__(self, N, R0, R, S, Z):
        self.N = N
        self.R0 = R0
        self.R = R
        self.S = S
        self.Z = Z

    @staticmethod
    def deser(v, n):
        if isinstance(v, integer):
            return v % n
        elif isinstance(v, int):
            return integer(v) % n
        else:
            raise RuntimeError("unknown type: {}".format(type(v)))

    def inFieldN(self):
        """
        Returns new Public Key with same values, in field N
        :return:
        """

        r = {k: self.deser(v, self.N) for k, v in self.R.items()}
        return CredDefPublicKey(self.N,
                                self.deser(self.R0, self.N),
                                r,
                                self.deser(self.S, self.N),
                                self.deser(self.Z, self.N))


class SerFmt(Enum):
    default = 1
    py3Int = 2
    base58 = 3


class ProofComponent:
    def __init__(self):
        self.evect = {}
        self.mvect = {}
        self.vvect = {}
        self.flatAttrs = None
        self.unrevealedAttrs = None
        self.tildeValues = None
        self.primeValues = None
        self.T = None
        self.c = None

class PredicateProofComponent(ProofComponent):
    def __init__(self):
        super().__init__()
        self.TauList = []
        self.CList = []
        self.C = {}
        self.u = {}
        self.r = {}

        self.alphavect = {}
        self.rvect = {}
        self.uvect = {}

        self.rtilde = {}
        self.utilde = {}
        self.alphatilde = 0

# Named tuples
T = TypeVar('T')

Credential = namedtuple("Credential", [CRED_A, CRED_E, CRED_V])

TildValue = namedtuple("TildValue", [MTILDE, ETILDE, VTILDE])

PrimeValue = namedtuple("PrimeValue", [APRIME, VPRIME, EPRIME])

SecretValue = namedtuple("SecretValue", ["tildValues", "primeValues", "T"])

CredDefSecretKey = namedtuple("CredDefSecretKey", ["p", "q"])

Proof = namedtuple('Proof', [C_VALUE, EVECT, MVECT, VVECT, APRIME])

SubProofPredicate = namedtuple('SubProofPredicate', ["alphavect", "rvect",
                                                     "uvect"])

PredicateProof = namedtuple('PredicateProof', ["subProofC", "subProofPredicate",
                                               "C", "CList"])
