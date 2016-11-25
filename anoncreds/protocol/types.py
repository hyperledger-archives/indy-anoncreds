from collections import namedtuple
from enum import Enum
from hashlib import sha256
from typing import TypeVar, Sequence, Dict, Set

from config.config import cmod


class AttribType:
    def __init__(self, name: str, encode: bool):
        self.name = name
        self.encode = encode

    def __eq__(x, y):
        return x.__dict__ == y.__dict__

    def __lt__(self, other):
        return self.name < other.name

    def __repr__(self):
        return str(self.__dict__)


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

    def __eq__(x, y):
        return sorted(x.names) == sorted(y.names) \
               and sorted(x.attrTypes) == sorted(y.attrTypes)

    def __repr__(self):
        return str(self.__dict__)


class Attribs:
    def __init__(self, credType: AttribDef = None, **vals):
        self.credType = credType if credType else AttribDef([], [])
        self._vals = vals

    def encoded(self):
        """
        This function will encode all the attributes to 256 bit integers

        :param attrs: The attributes to pass in credentials
        :return:
        """

        encoded = {}
        for i in range(len(self.credType.names)):
            name = self.credType.names[i]
            attr_types = self.credType.attrTypes[i]

            for at in attr_types:
                attrName = at.name
                if attrName in self._vals:
                    if at.encode:
                        encoded[attrName] = cmod.Conversion.bytes2integer(
                            sha256(str(self._vals[attrName]).encode()).digest())
                    else:
                        encoded[attrName] = self._vals[at.name]
        return encoded

    def __add__(self, other):
        vals = self._vals.copy()
        vals.update(other._vals)
        return Attribs(self.credType + other.credType, **vals)

    def __iter__(self):
        return self._vals.__iter__()

    def __getitem__(self, key):
        return self._vals[key]

    def keys(self):
        return self._vals.keys()

    def values(self):
        return self._vals.values()

    def items(self):
        return self._vals.items()

    def __repr__(self):
        return str(self.__dict__)

    def __eq__(x, y):
        return x.credType == y.credType \
               and x._vals == y._vals


class PublicParams:
    def __init__(self, Gamma, rho, g, h):
        self.Gamma = Gamma
        self.rho = rho
        self.g = g
        self.h = h


T = TypeVar('T')
VType = Set[int]
TailsType = Dict[int, cmod.integer]
TimestampType = int
ClaimInitDataType = namedtuple('ClaimInitDataType', 'U vPrime')


class ClaimDefinition:
    def __init__(self, name, version, attrNames, type, issuerId, id=None):
        self.name = name
        self.type = type
        self.version = version
        self.attrNames = attrNames
        self.issuerId = issuerId
        self.id = id

    def getKey(self):
        return ClaimDefinitionKey(self.name, self.version, self.issuerId)

    def __repr__(self):
        return str(self.__dict__)


class ClaimDefinitionKey:
    def __init__(self, name, version, issuerId):
        self.name = name
        self.version = version
        self.issuerId = issuerId

    def __key(self):
        return (self.name, self.version, self.issuerId)

    def __eq__(x, y):
        return x.__key() == y.__key()

    def __hash__(self):
        return hash(self.__key())

    def __repr__(self):
        return str(self.__dict__)


class ID:
    def __init__(self, claimDefKey: ClaimDefinitionKey = None, claimDefId=None, id=None):
        self.id = id
        self.claimDefId = claimDefId
        self.claimDefKey = claimDefKey


# CredentialDefinition = namedtuple('CredentialDefinition', ['name', 'version', 'attrNames', 'type'])

PublicKey = namedtuple('PublicKey', 'N Rms Rctxt R S Z')

SecretKey = namedtuple('SecretKey', 'pPrime qPrime')

RevocationPublicKey = namedtuple('RevocationPublicKey',
                                 'qr g h h0 h1 h2 htilde u pk y x')

RevocationSecretKey = namedtuple('RevocationSecretKey', 'x sk')

AccumulatorPublicKey = namedtuple('AccumulatorPublicKey', 'z')

AccumulatorSecretKey = namedtuple('AccumulatorSecretKey', 'gamma')


# TODO: now we assume >= predicate. Support other types of predicates
class Predicate:
    def __init__(self, attrName, value, type):
        self.attrName = attrName
        self.value = value
        self.type = type

    def __key(self):
        return (self.attrName, self.value, self.type)

    def __eq__(x, y):
        return x.__key() == y.__key()

    def __hash__(self):
        return hash(self.__key())


class PredicateGE(Predicate):
    def __init__(self, attrName, value):
        super().__init__(attrName, value, 'ge')


class Accumulator:
    def __init__(self, iA, acc, V: VType, L):
        self.iA = iA
        self.acc = acc
        self.V = V
        self.L = L
        self.currentI = 1

    def isFull(self):
        return self.currentI > self.L


# Accumulator = namedtuple('Accumulator', ['iA', 'acc', 'V', 'L'])

PrimaryClaim = namedtuple('PrimaryClaim', 'attrs m2 A e v')

Witness = namedtuple('Witness', 'sigmai ui gi omega V')

NonRevocationClaim = namedtuple('NonRevocationClaim', 'iA sigma c v witness gi i m2')

class ProofInput(namedtuple('ProofInput', 'revealedAttrs predicates ts seqNo')):
    def __new__(cls, revealedAttrs=[], predicates=[], ts=None, seqNo=None):
        return super(ProofInput, cls).__new__(cls, revealedAttrs, predicates, ts, seqNo)


class Claims(namedtuple('Claims', 'primaryClaim nonRevocClaim')):
    def __new__(cls, primaryClaim=None, nonRevocClaim=None):
        return super(Claims, cls).__new__(cls, primaryClaim, nonRevocClaim)


class ProofClaims(namedtuple('ProofClaims', 'claims revealedAttrs predicates')):
    def __new__(cls, claims=None, revealedAttrs=[], predicates=[]):
        return super(ProofClaims, cls).__new__(cls, claims, revealedAttrs, predicates)


class NonRevocProofXList:
    def __init__(self, rho=None, r=None, rPrime=None, rPrimePrime=None, rPrimePrimePrime=None, o=None, oPrime=None,
                 m=None, mPrime=None, t=None, tPrime=None, m2=None, s=None, c=None, group=None):
        self.rho = self._setValue(rho, group)
        self.r = self._setValue(r, group)
        self.rPrime = self._setValue(rPrime, group)
        self.rPrimePrime = self._setValue(rPrimePrime, group)
        self.rPrimePrimePrime = self._setValue(rPrimePrimePrime, group)
        self.o = self._setValue(o, group)
        self.oPrime = self._setValue(oPrime, group)
        self.m = self._setValue(m, group)
        self.mPrime = self._setValue(mPrime, group)
        self.t = self._setValue(t, group)
        self.tPrime = self._setValue(tPrime, group)
        self.m2 = self._setValue(m2, group)
        self.s = self._setValue(s, group)
        self.c = self._setValue(c, group)

    def _setValue(self, v=None, group=None):
        return v if v else group.random(cmod.ZR) if group else None

    def asList(self):
        return [self.rho, self.o, self.c, self.oPrime, self.m, self.mPrime, self.t, self.tPrime,
                self.m2, self.s, self.r, self.rPrime, self.rPrimePrime, self.rPrimePrimePrime]

    def fromList(self, values: Sequence):
        self.rho, self.o, self.c, self.oPrime, self.m, self.mPrime, self.t, self.tPrime, \
        self.m2, self.s, self.r, self.rPrime, self.rPrimePrime, self.rPrimePrimePrime = tuple(values)


class NonRevocProofCList:
    def __init__(self, E, D, A, G, W, S, U):
        self.E = E
        self.D = D
        self.A = A
        self.G = G
        self.W = W
        self.S = S
        self.U = U

    def asList(self):
        return [self.E, self.D, self.A, self.G, self.W, self.S, self.U]


class NonRevocProofTauList:
    def __init__(self, T1, T2, T3, T4, T5, T6, T7, T8):
        self.T1 = T1
        self.T2 = T2
        self.T3 = T3
        self.T4 = T4
        self.T5 = T5
        self.T6 = T6
        self.T7 = T7
        self.T8 = T8

    def asList(self):
        return [self.T1, self.T2, self.T3, self.T4, self.T5, self.T6, self.T7, self.T8]


class NonRevocInitProof:
    def __init__(self, CList: NonRevocProofCList, TauList: NonRevocProofTauList,
                 CListParams: NonRevocProofXList, TauListParams: NonRevocProofXList):
        self.CList = CList
        self.TauList = TauList
        self.CListParams = CListParams
        self.TauListParams = TauListParams

    def asCList(self):
        return self.CList.asList()

    def asTauList(self):
        return self.TauList.asList()


class PrimaryEqualInitProof:
    def __init__(self, c1: PrimaryClaim, Aprime, T, eTilde, ePrime, vTilde, vPrime, mTilde, m1Tilde, m2Tilde,
                 unrevealedAttrs, revealedAttrs):
        self.c1 = c1
        self.Aprime = Aprime
        self.T = T
        self.eTilde = eTilde
        self.ePrime = ePrime
        self.vTilde = vTilde
        self.vPrime = vPrime
        self.mTilde = mTilde
        self.m1Tilde = m1Tilde
        self.m2Tilde = m2Tilde
        self.unrevealedAttrs = unrevealedAttrs
        self.revealedAttrs = revealedAttrs

    def asCList(self):
        return [self.Aprime]

    def asTauList(self):
        return [self.T]


class PrimaryEqualProof:
    def __init__(self, e, v, m, m1, m2, Aprime, revealedAttrNames):
        self.e = e
        self.v = v
        self.m = m
        self.m1 = m1
        self.m2 = m2
        self.Aprime = Aprime
        self.revealedAttrNames = revealedAttrNames


class PrimaryPrecicateGEInitProof:
    def __init__(self, CList, TauList, u, uTilde, r, rTilde, alphaTilde, predicate, T):
        self.CList = CList
        self.TauList = TauList
        self.uTilde = uTilde
        self.u = u
        self.rTilde = rTilde
        self.r = r
        self.alphaTilde = alphaTilde
        self.predicate = predicate
        self.T = T

    def asCList(self):
        return self.CList

    def asTauList(self):
        return self.TauList


class PrimaryPredicateGEProof:
    def __init__(self, u, r, alpha, mj, T, predicate):
        self.u = u
        self.r = r
        self.alpha = alpha
        self.mj = mj
        self.T = T
        self.predicate = predicate


class PrimaryInitProof:
    def __init__(self, eqProof: PrimaryEqualInitProof, geProofs: Sequence[PrimaryPrecicateGEInitProof]):
        self.eqProof = eqProof
        self.geProofs = geProofs

    def asCList(self):
        CList = self.eqProof.asCList()
        for geProof in self.geProofs:
            CList += geProof.asCList()
        return CList

    def asTauList(self):
        TauList = self.eqProof.asTauList()
        for geProof in self.geProofs:
            TauList += geProof.asTauList()
        return TauList


class InitProof:
    def __init__(self, nonRevocInitProof: NonRevocInitProof = None, primaryInitProof: PrimaryInitProof = None):
        self.nonRevocInitProof = nonRevocInitProof
        self.primaryInitProof = primaryInitProof


class NonRevocProof:
    def __init__(self, XList: NonRevocProofXList, CProof: NonRevocProofCList):
        self.XList = XList
        self.CProof = CProof


class PrimaryProof:
    def __init__(self, eqProof: PrimaryEqualProof, geProofs: Sequence[PrimaryPredicateGEProof]):
        self.eqProof = eqProof
        self.geProofs = geProofs


class Proof:
    def __init__(self, primaryProof: PrimaryProof, nonRevocProof: NonRevocProof = None):
        self.nonRevocProof = nonRevocProof
        self.primaryProof = primaryProof


class FullProof:
    def __init__(self, cHash, proofs: Dict[ClaimDefinitionKey, Proof],
                 CList: Sequence[T]):
        self.cHash = cHash
        self.proofs = proofs
        self.CList = CList

    def getCredDefs(self):
        return self.proofs.keys()


class SerFmt(Enum):
    default = 1
    py3Int = 2
    base58 = 3
