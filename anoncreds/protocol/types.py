from collections import namedtuple
from enum import Enum
from hashlib import sha256
from typing import TypeVar, Sequence, Dict, Set

from charm.core.math.integer import integer
from charm.core.math.pairing import ZR
from charm.toolbox.conversion import Conversion

from anoncreds.protocol.globals import APRIME, ETILDE, MTILDE, VTILDE, EPRIME, VPRIME, \
    CRED_A, CRED_E, CRED_V


class AttribType:
    def __init__(self, name: str, encode: bool):
        self.name = name
        self.encode = encode

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

    def __repr__(self):
        return str(self.__dict__)


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

        encoded = {}
        for i in range(len(self.credType.names)):
            name = self.credType.names[i]
            attr_types = self.credType.attrTypes[i]

            for at in attr_types:
                if at.encode:
                    encoded[at.name] = Conversion.bytes2integer(
                        sha256(str(self._vals[at.name]).encode()).digest())
                else:
                    encoded[at.name] = self._vals[at.name]
        return encoded

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

    def __repr__(self):
        return str(self.__dict__)


class PublicParams:
    def __init__(self, Gamma, rho, g, h):
        self.Gamma = Gamma
        self.rho = rho
        self.g = g
        self.h = h


class PublicKey:
    def __init__(self, N, Rms, Rctxt, R, S, Z, attrNames):
        self.N = N
        self.Rms = Rms
        self.Rctxt = Rctxt
        self.R = R
        self.S = S
        self.Z = Z
        self.attrNames = attrNames

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
        return PublicKey(self.N,
                         self.deser(self.Rms, self.N),
                         self.deser(self.Rctxt, self.N),
                         r,
                         self.deser(self.S, self.N),
                         self.deser(self.Z, self.N),
                         self.attrNames)


class SecretKey:
    def __init__(self, p, q):
        self.p = p
        self.q = q

    def getPPrime(self):
        return (self.p - 1) / 2

    def getQPrime(self):
        return (self.q - 1) / 2


class RevocationPublicKey:
    def __init__(self, qr, g, h, h0, h1, h2, htilde, u, pk, y, x, groupType):
        self.qr = qr
        self.g = g
        self.h = h
        self.h0 = h0
        self.h1 = h1
        self.h2 = h2
        self.htilde = htilde
        self.u = u
        self.pk = pk
        self.y = y
        self.x = x
        self.groupType = groupType


class RevocationSecretKey:
    def __init__(self, x, sk):
        self.x = x
        self.sk = sk


class AccumulatorPublicKey:
    def __init__(self, z):
        self.z = z


class AccumulatorSecretKey:
    def __init__(self, gamma):
        self.gamma = gamma


T = TypeVar('T')
VType = Set[int]
GType = Dict[int, integer]


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


class SecretData:
    def __init__(self, pk: PublicKey, sk: SecretKey,
                 pkR: RevocationPublicKey, skR: RevocationSecretKey,
                 accum: Accumulator, g: GType,
                 pkAccum: AccumulatorPublicKey, skAccum: AccumulatorSecretKey):
        self.pk = pk
        self.sk = sk
        self.pkR = pkR
        self.skR = skR
        self.accum = accum
        self.g = g
        self.pkAccum = pkAccum
        self.skAccum = skAccum


class PublicData:
    def __init__(self, pk: PublicKey, pkR: RevocationPublicKey,
                 accum: Accumulator, g: GType,
                 pkAccum: AccumulatorPublicKey):
        self.pk = pk
        self.pkR = pkR
        self.accum = accum
        self.g = g
        self.pkAccum = pkAccum


class PrimaryClaim:
    def __init__(self, attrs: Dict[str, T], m2, A, e, v):
        self.attrs = attrs
        self.m2 = m2
        self.A = A
        self.e = e
        self.v = v


class Witness:
    def __init__(self, sigmai, ui, gi, omega, V: VType):
        self.sigmai = sigmai
        self.ui = ui
        self.gi = gi
        self.omega = omega
        self.V = V


class NonRevocationClaim:
    def __init__(self, iA, sigma, c, v, witness: Witness, gi, i, m2):
        self.iA = iA
        self.sigma = sigma
        self.c = c
        self.v = v
        self.witness = witness
        self.gi = gi
        self.i = i
        self.m2 = m2


class ProofInput:
    def __init__(self, revealedAttrs: Sequence[str], predicates: Sequence[Predicate]):
        self.revealedAttrs = revealedAttrs
        self.predicates = predicates


class Claims:
    def __init__(self, primaryClaim: PrimaryClaim = None, nonRevocClaim: NonRevocationClaim = None):
        self.nonRevocClaim = nonRevocClaim
        self.primaryClaim = primaryClaim


class ProofClaims:
    def __init__(self, claims: Claims, revealedAttrs: Sequence[str] = None, predicates: Sequence[Predicate] = None):
        self.claims = claims
        self.revealedAttrs = revealedAttrs if revealedAttrs else []
        self.predicates = predicates if predicates else []

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


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
        return v if v else group.random(ZR) if group else None

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
    def __init__(self, nonRevocProof: NonRevocProof, primaryProof: PrimaryProof):
        self.nonRevocProof = nonRevocProof
        self.primaryProof = primaryProof


class FullProof:
    def __init__(self, cHash, proofs: Dict[str, Proof],
                 CList: Sequence[T]):
        self.cHash = cHash
        self.proofs = proofs
        self.CList = CList

    def getIssuerIds(self):
        return self.proofs.keys()


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

    def __repr__(self):
        return str(self.__dict__)


class CredDefSecretKey:
    def __init__(self, p, q):
        self.p = p
        self.q = q


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


Credential = namedtuple("Credential", [CRED_A, CRED_E, CRED_V])

TildValue = namedtuple("TildValue", [MTILDE, ETILDE, VTILDE])

PrimeValue = namedtuple("PrimeValue", [APRIME, VPRIME, EPRIME])

SecretValue = namedtuple("SecretValue", ["tildValues", "primeValues", "T"])

CredDefSecretKey = namedtuple("CredDefSecretKey", ["p", "q"])

# Proof = namedtuple('Proof', [C_VALUE, EVECT, MVECT, VVECT, APRIME])

SubProofPredicate = namedtuple('SubProofPredicate', ["alphavect", "rvect",
                                                     "uvect"])

PredicateProof = namedtuple('PredicateProof', ["subProofC", "subProofPredicate",
                                               "C", "CList"])
