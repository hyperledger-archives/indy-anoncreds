from collections import namedtuple
from enum import Enum
from hashlib import sha256
from typing import TypeVar

from charm.toolbox.conversion import Conversion

from anoncreds.protocol.globals import APRIME, EVECT, MVECT, VVECT, C_VALUE, \
    ETILDE, MTILDE, VTILDE, EPRIME, VPRIME, CRED_A, CRED_E, CRED_V


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

    def get(self, key):
        return self._vals.get(key)


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

Proof = namedtuple('Proof', [C_VALUE, EVECT, MVECT, VVECT, APRIME])

SubProofPredicate = namedtuple('SubProofPredicate', ["alphavect", "rvect",
                                                     "uvect"])

PredicateProof = namedtuple('PredicateProof', ["subProofC", "subProofPredicate",
                                               "C", "CList"])
