from collections import namedtuple
from enum import Enum
from hashlib import sha256
from typing import TypeVar

from charm.core.math.integer import integer
from charm.toolbox.conversion import Conversion


class AttribType:
    def __init__(self, name: str, encode: bool):
        self.name = name
        self.encode = encode


# FIXME Why the plural(Attribs) in class name?
class AttribsDef:
    def __init__(self, name, attr_types):
        if isinstance(name, str):
            # FIXME CamelCase or snake_case. Stick to one of them.
            self.name_a = [name]
            self.attr_types_a = [attr_types]
        else:
            self.name_a = name
            self.attr_types_a = attr_types

    @property
    def name(self):
        return ', '.join(self.name_a)

    def __getattr__(self, item):
        for attr_types in self.attr_types_a:
            for at in attr_types:
                if item == at.name:
                    return at
            raise AttributeError

    def __add__(self, other):
        return AttribsDef(self.name_a + other.name_a,
                          self.attr_types_a + other.attr_types_a)

    def attribs(self, **vals):
        return Attribs(self, **vals)

    # FIXME inconsistent naming. Call it names
    def getNames(self):
        return [at.name
                for attr_types in self.attr_types_a
                for at in attr_types]


class Attribs:
    def __init__(self, credType: AttribsDef, **vals):
        self.credType = credType
        self.vals = vals

    def encoded(self):
        """
        This function will encode all the attributes to 256 bit integers

        :param attrs: The attributes to pass in credentials
        :return:
        """
        named = {}
        for i in range(len(self.credType.name_a)):
            name = self.credType.name_a[i]
            attr_types = self.credType.attr_types_a[i]
            encoded = {}
            for at in attr_types:
                if at.encode:
                    encoded[at.name] = Conversion.bytes2integer(
                        sha256(str(self.vals[at.name]).encode()).digest())
                else:
                    encoded[at.name] = self.vals[at.name]
            named[name] = encoded
        return named

    def __add__(self, other):
        vals = self.vals.copy()
        vals.update(other.vals)
        return Attribs(self.credType + other.credType, **vals)

    def __iter__(self):
        return self.vals.__iter__()

    # def __getitem__(self, item):
    #     return self.vals.get(item)
    #
    # def __len__(self):
    #     return self.vals.__len__()

    # FIXME Cleanup this mess by inheriting dict and using proper dunder methods
    def keys(self):
        return self.vals.keys()

    def values(self):
        return self.vals.values()

    def items(self):
        return self.vals.items()


# Named tuples
T = TypeVar('T')

Credential = namedtuple("Credential", ["A", "e", "v"])


# FIXME Rename this class. This is the PK of a credential definition, not Issuer
class IssuerPublicKey:
    def __init__(self, N, R, S, Z):
        self.N = N
        self.R = R
        self.S = S
        self.Z = Z

    # FIXME Write the whole word, we save nothing with a few characters.
    # Short versions breed inconsistency and cause confusion.
    @staticmethod
    def deser(v, n):
        if isinstance(v, integer):
            return v % n
        elif isinstance(v, int):
            return integer(v) % n
        else:
            raise RuntimeError("unknown type: {}".format(type(v)))

    def inFieldN(self):
        # FIXME There must be a new line after the description in the docstring.
        # FIXME Fix it in all other files as well.
        """
        Returns new Public Key with same values, in field N
        :return:
        """
        r = {k: self.deser(v, self.N) for k, v in self.R.items()}
        return IssuerPublicKey(self.N, r,
                               self.deser(self.S, self.N),
                               self.deser(self.Z, self.N))

# FIXME Find all such stray namedtuples and move them to one module.

# IssuerPublicKey = namedtuple("IssuerPublicKey", ["N", "R", "S", "Z"])

CredDefSecretKey = namedtuple("CredDefSecretKey", ["p", "q"])

Proof = namedtuple('Proof', ["c", "evect", "mvect", "vvect", "Aprime"])

SubProofPredicate = namedtuple('SubProofPredicate', ["alphavect", "rvect",
                                                     "uvect"])

PredicateProof = namedtuple('PredicateProof', ["subProofC", "subProofPredicate",
                                               "C", "CList"])


class SerFmt(Enum):
    charmInteger = 1
    py3Int = 2
    base58 = 3
