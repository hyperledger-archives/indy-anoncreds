from collections import namedtuple
from hashlib import sha256
from typing import TypeVar, Sequence, Dict, Set

from anoncreds.protocol.utils import toDictWithStrValues, \
    fromDictWithStrValues, deserializeFromStr
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


PublicParams = namedtuple('PublicParams', 'Gamma, rho, g, h')

T = TypeVar('T')
VType = Set[int]
TailsType = Dict[int, cmod.integer]
TimestampType = int


class NamedTupleStrSerializer:
    def toStrDict(self):
        return toDictWithStrValues(self._asdict())

    @classmethod
    def fromStrDict(cls, d):
        d = fromDictWithStrValues(d)
        return cls(**d)


class StrSerializer:
    def toStrDict(self):
        return toDictWithStrValues(self.__dict__)

    @classmethod
    def fromStrDict(cls, d):
        d = fromDictWithStrValues(d)
        return cls(**d)


class SchemaKey(
    namedtuple('SchemaKey', 'name, version, issuerId'),
    NamedTupleStrSerializer):
    def __hash__(self):
        keys = (self.name, self.version, self.issuerId)
        return hash(keys)


class ID(namedtuple('ID', 'schemaKey, schemaId, seqId')):
    def __new__(cls, schemaKey: SchemaKey = None, schemaId=None,
                seqId=None):
        return super(ID, cls).__new__(cls, schemaKey, schemaId, seqId)


class Schema(namedtuple('Schema',
                        'name, version, attrNames, schemaType, '
                        'issuerId, seqId'),
             NamedTupleStrSerializer):
    def __new__(cls, name, version, attrNames, schemaType, issuerId, seqId=None):
        return super(Schema, cls).__new__(cls, name, version,
                                          attrNames, schemaType, issuerId,
                                          seqId)

    def getKey(self):
        return SchemaKey(self.name, self.version, self.issuerId)


class PublicKey(namedtuple('PublicKey', 'N, Rms, Rctxt, R, S, Z, seqId'),
                NamedTupleStrSerializer):
    def __new__(cls, N, Rms, Rctxt, R, S, Z, seqId=None):
        return super(PublicKey, cls).__new__(cls, N, Rms, Rctxt, R, S, Z, seqId)


SecretKey = namedtuple('SecretKey', 'pPrime, qPrime')


class RevocationPublicKey(namedtuple('RevocationPublicKey',
                                     'qr, g, h, h0, h1, h2, htilde, u, pk, y, x, seqId'),
                          NamedTupleStrSerializer):
    def __new__(cls, qr, g, h, h0, h1, h2, htilde, u, pk, y, x, seqId=None):
        return super(RevocationPublicKey, cls).__new__(cls, qr, g, h, h0, h1,
                                                       h2, htilde, u, pk, y, x,
                                                       seqId)


RevocationSecretKey = namedtuple('RevocationSecretKey', 'x, sk')


class AccumulatorPublicKey(namedtuple('AccumulatorPublicKey', 'z, seqId'),
                           NamedTupleStrSerializer):
    def __new__(cls, z, seqId=None):
        return super(AccumulatorPublicKey, cls).__new__(cls, z, seqId)


AccumulatorSecretKey = namedtuple('AccumulatorSecretKey', 'gamma')


class Predicate(namedtuple('Predicate', 'attrName, value, type'),
                NamedTupleStrSerializer):
    def __key(self):
        return self.attrName, self.value, self.type

    def __eq__(x, y):
        return x.__key() == y.__key()

    def __hash__(self):
        return hash(self.__key())


# TODO: now we consdider only  >= predicate. Support other types of predicates
class PredicateGE(Predicate):
    def __new__(cls, attrName, value, type='ge'):
        return super(PredicateGE, cls).__new__(cls, attrName, value, type)


class Accumulator:
    def __init__(self, iA, acc, V: VType, L):
        self.iA = iA
        self.acc = acc
        self.V = V
        self.L = L
        self.currentI = 1

    def isFull(self):
        return self.currentI > self.L


ClaimInitDataType = namedtuple('ClaimInitDataType', 'U, vPrime')


class ClaimRequest(namedtuple('ClaimRequest', 'userId, U, Ur'),
                   NamedTupleStrSerializer):
    def __new__(cls, userId, U, Ur=None):
        return super(ClaimRequest, cls).__new__(cls, userId, U, Ur)


# Accumulator = namedtuple('Accumulator', ['iA', 'acc', 'V', 'L'])

class PrimaryClaim(
    namedtuple('PrimaryClaim', 'attrs, encodedAttrs, m2, A, e, v'),
    NamedTupleStrSerializer):
    pass


class Witness(namedtuple('Witness', 'sigmai, ui, gi, omega, V'),
              NamedTupleStrSerializer):
    pass


class NonRevocationClaim(
    namedtuple('NonRevocationClaim', 'iA, sigma, c, v, witness, gi, i, m2'),
    NamedTupleStrSerializer):
    @classmethod
    def fromStrDict(cls, d):
        d = fromDictWithStrValues(d)
        witness = Witness(**d['witness'])
        result = cls(**d)
        return result._replace(witness=witness)


class Claims(namedtuple('Claims', 'primaryClaim, nonRevocClaim'),
             NamedTupleStrSerializer):
    def __new__(cls, primaryClaim, nonRevocClaim=None):
        return super(Claims, cls).__new__(cls, primaryClaim, nonRevocClaim)

    @classmethod
    def fromStrDict(cls, d):
        primary = PrimaryClaim.fromStrDict(d['primaryClaim'])
        nonRevoc = None
        if 'nonRevocClaim' in d:
            nonRevoc = NonRevocationClaim.fromStrDict(d['nonRevocClaim'])
        return Claims(primaryClaim=primary, nonRevocClaim=nonRevoc)


class ProofInput(
    namedtuple('ProofInput', 'revealedAttrs, predicates, ts, seqNo'),
    NamedTupleStrSerializer):
    def __new__(cls, revealedAttrs=None, predicates=None, ts=None, seqNo=None):
        return super(ProofInput, cls).__new__(cls, revealedAttrs or [],
                                              predicates or [],
                                              ts, seqNo)

    @classmethod
    def fromStrDict(cls, d):
        d = fromDictWithStrValues(d)
        predicates = [Predicate.fromStrDict(v) for v in d['predicates']]
        result = cls(**d)
        return result._replace(predicates=predicates)


class ProofClaims(
    namedtuple('ProofClaims', 'claims, revealedAttrs, predicates')):
    def __new__(cls, claims=None, revealedAttrs=None, predicates=None):
        return super(ProofClaims, cls).__new__(cls, claims, revealedAttrs or [],
                                               predicates or [])


class NonRevocProofXList(
    namedtuple('NonRevocProofXList',
               'rho, r, rPrime, rPrimePrime, rPrimePrimePrime, o, oPrime, m, mPrime, t, tPrime, m2, s, c'),
    NamedTupleStrSerializer):
    def __new__(cls, rho=None, r=None, rPrime=None, rPrimePrime=None,
                rPrimePrimePrime=None, o=None, oPrime=None,
                m=None, mPrime=None, t=None, tPrime=None, m2=None, s=None,
                c=None, group=None):
        return super(NonRevocProofXList, cls).__new__(cls,
                                                      rho=cls._setValue(rho,
                                                                        group),
                                                      r=cls._setValue(r, group),
                                                      rPrime=cls._setValue(
                                                          rPrime, group),
                                                      rPrimePrime=cls._setValue(
                                                          rPrimePrime, group),
                                                      rPrimePrimePrime=cls._setValue(
                                                          rPrimePrimePrime,
                                                          group),
                                                      o=cls._setValue(o, group),
                                                      oPrime=cls._setValue(
                                                          oPrime, group),
                                                      m=cls._setValue(m, group),
                                                      mPrime=cls._setValue(
                                                          mPrime, group),
                                                      t=cls._setValue(t, group),
                                                      tPrime=cls._setValue(
                                                          tPrime, group),
                                                      m2=cls._setValue(m2,
                                                                       group),
                                                      s=cls._setValue(s, group),
                                                      c=cls._setValue(c, group))

    @staticmethod
    def _setValue(v=None, group=None):
        return v if v else group.random(cmod.ZR) if group else None

    def asList(self):
        return [self.rho, self.o, self.c, self.oPrime, self.m, self.mPrime,
                self.t, self.tPrime,
                self.m2, self.s, self.r, self.rPrime, self.rPrimePrime,
                self.rPrimePrimePrime]

    @staticmethod
    def fromList(values: Sequence):
        rho, o, c, oPrime, m, mPrime, t, tPrime, m2, s, r, rPrime, rPrimePrime, rPrimePrimePrime = tuple(
            values)
        return NonRevocProofXList(rho=rho, o=o, c=c, oPrime=oPrime, m=m,
                                  mPrime=mPrime, t=t, tPrime=tPrime,
                                  m2=m2, s=s, r=r, rPrime=rPrime,
                                  rPrimePrime=rPrimePrime,
                                  rPrimePrimePrime=rPrimePrimePrime)


class NonRevocProofCList(
    namedtuple('NonRevocProofCList', 'E, D, A, G, W, S, U'),
    NamedTupleStrSerializer):
    def asList(self):
        return [self.E, self.D, self.A, self.G, self.W, self.S, self.U]


class NonRevocProofTauList(
    namedtuple('NonRevocProofTauList', 'T1, T2, T3, T4, T5, T6, T7, T8'),
    NamedTupleStrSerializer):
    def asList(self):
        return [self.T1, self.T2, self.T3, self.T4, self.T5, self.T6, self.T7,
                self.T8]


class NonRevocInitProof(namedtuple('NonRevocInitProof',
                                   'CList, TauList, CListParams, TauListParams'),
                        NamedTupleStrSerializer):
    def asCList(self):
        return self.CList.asList()

    def asTauList(self):
        return self.TauList.asList()


class PrimaryEqualInitProof(namedtuple('PrimaryEqualInitProof',
                                       'c1, Aprime, T, eTilde, ePrime, vTilde, vPrime, \
                                       mTilde, m1Tilde, m2Tilde, unrevealedAttrs, revealedAttrs'),
                            NamedTupleStrSerializer):
    def asCList(self):
        return [self.Aprime]

    def asTauList(self):
        return [self.T]


class PrimaryPrecicateGEInitProof(
    namedtuple('PrimaryPrecicateGEInitProof',
               'CList, TauList, u, uTilde, r, rTilde, alphaTilde, predicate, T'),
    NamedTupleStrSerializer):
    def asCList(self):
        return self.CList

    def asTauList(self):
        return self.TauList


class PrimaryInitProof(namedtuple('PrimaryInitProof', 'eqProof, geProofs'),
                       NamedTupleStrSerializer):
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


class InitProof(namedtuple('InitProof', 'nonRevocInitProof, primaryInitProof'),
                NamedTupleStrSerializer):
    def __new__(cls, nonRevocInitProof: NonRevocInitProof = None,
                primaryInitProof: PrimaryInitProof = None):
        return super(InitProof, cls).__new__(cls, nonRevocInitProof,
                                             primaryInitProof)


class PrimaryEqualProof(namedtuple('PrimaryEqualProof',
                                   'e, v, m, m1, m2, Aprime, revealedAttrNames'),
                        NamedTupleStrSerializer):
    pass


class PrimaryPredicateGEProof(
    namedtuple('PrimaryPredicateGEProof', 'u, r, alpha, mj, T, predicate'),
    NamedTupleStrSerializer):
    @classmethod
    def fromStrDict(cls, d):
        d = fromDictWithStrValues(d)
        predicate = PredicateGE(**d['predicate'])
        result = cls(**d)
        return result._replace(predicate=predicate)


class NonRevocProof(namedtuple('NonRevocProof', 'XList CProof'),
                    NamedTupleStrSerializer):
    @classmethod
    def fromStrDict(cls, d):
        XList = NonRevocProofXList.fromStrDict(d['XList'])
        CProof = NonRevocProofCList.fromStrDict(d['CProof'])
        return NonRevocProof(XList=XList, CProof=CProof)


class PrimaryProof(namedtuple('PrimaryProof', 'eqProof, geProofs'),
                   NamedTupleStrSerializer):
    def __new__(cls, eqProof: PrimaryEqualProof,
                geProofs: Sequence[PrimaryPredicateGEProof]):
        return super(PrimaryProof, cls).__new__(cls, eqProof, geProofs)

    @classmethod
    def fromStrDict(cls, d):
        eqProof = PrimaryEqualProof.fromStrDict(d['eqProof'])
        geProofs = [PrimaryPredicateGEProof.fromStrDict(v) for v in
                    d['geProofs']]
        return PrimaryProof(eqProof=eqProof, geProofs=geProofs)


class Proof(namedtuple('Proof', 'primaryProof, nonRevocProof'),
            NamedTupleStrSerializer):
    def __new__(cls, primaryProof: PrimaryProof,
                nonRevocProof: NonRevocProof = None):
        return super(Proof, cls).__new__(cls, primaryProof, nonRevocProof)

    @classmethod
    def fromStrDict(cls, d):
        primaryProof = PrimaryProof.fromStrDict(d['primaryProof'])
        nonRevocProof = None
        if 'nonRevocProof' in d:
            nonRevocProof = NonRevocProof.fromStrDict(d['nonRevocProof'])
        return Proof(primaryProof=primaryProof, nonRevocProof=nonRevocProof)


class FullProof(namedtuple('FullProof', 'cHash, schemaKeys, proofs, CList'),
                NamedTupleStrSerializer):
    def getCredDefs(self):
        return self.proofs.keys()

    @classmethod
    def fromStrDict(cls, d):
        cHash = deserializeFromStr(d['cHash'])
        schemaKeys = [SchemaKey.fromStrDict(v) for v in
                      d['schemaKeys']]
        proofs = [Proof.fromStrDict(v) for v in d['proofs']]
        CList = [deserializeFromStr(v) for v in d['CList']]
        return FullProof(cHash=cHash, schemaKeys=schemaKeys, proofs=proofs,
                         CList=CList)
