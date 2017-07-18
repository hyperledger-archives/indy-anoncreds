import os
from collections import namedtuple
from typing import TypeVar, Sequence, Dict, Set

from anoncreds.protocol.utils import toDictWithStrValues, \
    fromDictWithStrValues, deserializeFromStr, encodeAttr, crypto_int_to_str, to_crypto_int, isCryptoInteger, \
    intToArrayBytes, bytesToInt
from config.config import cmod
from typing import NamedTuple
import uuid

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
                        encoded[attrName] = encodeAttr(self._vals[attrName])
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
TimestampType = int

class Tails:

    def __init__(self):
        self.g = {}
        self.gprime = {}

    def addValue(self, index, gVal, gprimeVal):
        self.g[index] = gVal
        self.gprime[index] = gprimeVal


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
    def __new__(cls, name=None, version=None, issuerId=None):
        return super(SchemaKey, cls).__new__(cls, name, version, issuerId)

    def __hash__(self):
        keys = (self.name, self.version, self.issuerId)
        return hash(keys)

    def __str__(self):
        rtn = list()
        rtn.append('Schema Key')
        rtn.append("    Name: {}".format(str(self.name)))
        rtn.append("    Version: {}".format(str(self.version)))
        rtn.append("    IssuerId: {}".format(str(self.issuerId)))

        return os.linesep.join(rtn)


class ID(namedtuple('ID', 'schemaKey, schemaId, seqId')):
    def __new__(cls, schemaKey: SchemaKey = None, schemaId=None,
                seqId=None):
        return super(ID, cls).__new__(cls, schemaKey, schemaId, seqId)


class Schema(namedtuple('Schema',
                        'name, version, attrNames, issuerId, seqId'),
             NamedTupleStrSerializer):
    def __new__(cls, name, version, attrNames, issuerId, seqId=None):
        return super(Schema, cls).__new__(cls,
                                          name,
                                          version,
                                          attrNames,
                                          issuerId,
                                          seqId)

    def getKey(self):
        return SchemaKey(self.name, self.version, self.issuerId)


class PublicKey(namedtuple('PublicKey', 'N, Rms, Rctxt, R, S, Z, seqId'),
                NamedTupleStrSerializer):
    def __new__(cls, N, Rms, Rctxt, R, S, Z, seqId=None):
        return super(PublicKey, cls).__new__(cls, N, Rms, Rctxt, R, S, Z, seqId)

    def __eq__(self, other):
        return self.N == other.N and self.Rms == other.Rms \
               and self.Rctxt == other.Rctxt and self.S == other.S \
               and self.Z == other.Z and self.seqId == other.seqId \
               and dict(self.R) == dict(other.R)

    def to_str_dict(self):
        public_key = {
            'n': str(crypto_int_to_str(self.N)),
            's': str(crypto_int_to_str(self.S)),
            'rms': str(crypto_int_to_str(self.Rms)),
            'rctxt': str(crypto_int_to_str(self.Rctxt)),
            'z': str(crypto_int_to_str(self.Z)),
            'r': {k: str(crypto_int_to_str(v)) for k, v in self.R.items()}
        }

        return public_key

    @classmethod
    def from_str_dict(cls, data):
        N = to_crypto_int(data['n'])
        Rms = to_crypto_int(data['rms'], data['n'])
        Rctxt = to_crypto_int(data['rctxt'], data['n'])
        S = to_crypto_int(data['s'], data['n'])
        Z = to_crypto_int(data['z'], data['n'])
        R = {k: to_crypto_int(v, data['n']) for k, v in data['r'].items()}

        return cls(N, Rms, Rctxt, R, S, Z)


class SecretKey(namedtuple('SecretKey', 'pPrime, qPrime'),
                NamedTupleStrSerializer):
    pass


class RevocationPublicKey(namedtuple('RevocationPublicKey',
                                     'qr, g, gprime, h, h0, h1, h2, htilde, hhat, u, pk, y, seqId'),
                          NamedTupleStrSerializer):
    def __new__(cls, qr, g, gprime, h, h0, h1, h2, htilde, hhat, u, pk, y, seqId=None):
        return super(RevocationPublicKey, cls).__new__(cls, qr, g, gprime, h, h0, h1,
                                                       h2, htilde, hhat, u, pk, y,
                                                       seqId)


class RevocationSecretKey(namedtuple('RevocationSecretKey', 'x, sk'),
                          NamedTupleStrSerializer):
    pass


class AccumulatorPublicKey(namedtuple('AccumulatorPublicKey', 'z, seqId'),
                           NamedTupleStrSerializer):
    def __new__(cls, z, seqId=None):
        return super(AccumulatorPublicKey, cls).__new__(cls, z, seqId)


class AccumulatorSecretKey(
    namedtuple('AccumulatorSecretKey', 'gamma'), NamedTupleStrSerializer):
    pass


class Predicate(namedtuple('Predicate', 'attrName, value, type, schema_seq_no, issuer_did'),
                NamedTupleStrSerializer):
    def __new__(cls, attrName, value, type, schema_seq_no=None, issuer_did=None):
        return super(Predicate, cls).__new__(cls, attrName, value, type, schema_seq_no, issuer_did)

    def __key(self):
        return self.attrName, self.value, self.type

    def __eq__(x, y):
        return x.__key() == y.__key()

    def __hash__(self):
        return hash(self.__key())

    def to_str_dict(self):
        return {
            'attr_name': self.attrName,
            'value': self.value,
            'p_type': self.type,
            'schema_seq_no': self.schema_seq_no,
            'issuer_did': self.issuer_did
        }

    @classmethod
    def from_str_dict(cls, d):
        attrName = d['attr_name']
        value = d['value']
        type = d['p_type']
        schema_seq_no = int(d['schema_seq_no']) if (('schema_seq_no' in d) and d['schema_seq_no']) else None
        issuer_did = int(d['issuer_did']) if (('issuer_did' in d) and d['issuer_did']) else None
        return PredicateGE(attrName=attrName, value=value, type=type,
                         schema_seq_no=schema_seq_no, issuer_did=issuer_did)


# TODO: now we consdider only  >= predicate. Support other types of predicates
class PredicateGE(Predicate):
    def __new__(cls, attrName, value, type='GE', schema_seq_no=None, issuer_did=None):
        return super(PredicateGE, cls).__new__(cls, attrName, value, type, schema_seq_no, issuer_did)


class Accumulator:
    def __init__(self, iA, acc, V: VType, L):
        self.iA = iA
        self.acc = acc
        self.V = V
        self.L = L
        self.currentI = 1

    def isFull(self):
        return self.currentI > self.L

    def __eq__(self, other):
        return self.iA == other.iA and self.acc == other.acc \
               and self.V == other.V and self.L == other.L \
               and self.currentI == other.currentI


ClaimInitDataType = namedtuple('ClaimInitDataType', 'U, vPrime')


class ClaimRequest(namedtuple('ClaimRequest', 'userId, U, Ur'),
                   NamedTupleStrSerializer):
    def __new__(cls, userId, U, Ur=None):
        return super(ClaimRequest, cls).__new__(cls, userId, U, Ur)

    def to_str_dict(self):
        return {
            'prover_did': str(self.userId),
            'u': str(crypto_int_to_str(self.U)),
            'ur': self.Ur
        }

    @classmethod
    def from_str_dict(cls, data, n):
        u = to_crypto_int(data['u'], str(n))

        return cls(userId=data['prover_did'], U=u, Ur=data['ur'])


# Accumulator = namedtuple('Accumulator', ['iA', 'acc', 'V', 'L'])

class PrimaryClaim(
    namedtuple('PrimaryClaim', 'm2, A, e, v'),
    NamedTupleStrSerializer):

    def to_str_dict(self):
        return {
            'm2': str(crypto_int_to_str(self.m2)),
            'a': str(crypto_int_to_str(self.A)),
            'e': str(self.e),
            'v': str(self.v)
        }

    @classmethod
    def from_str_dict(cls, data, n):
        m2 = to_crypto_int(data['m2'])
        a = to_crypto_int(data['a'], str(n))
        e = int(data['e'])
        v = int(data['v'])

        return cls(m2=m2, A=a, e=e, v=v)


class Witness(namedtuple('Witness', 'sigmai, ui, gi, omega, V'),
              NamedTupleStrSerializer):
    pass


class NonRevocationClaim(
    namedtuple('NonRevocationClaim', 'iA, sigma, c, v, witness,i, m2'),
    NamedTupleStrSerializer):
    @classmethod
    def fromStrDict(cls, d):
        d = fromDictWithStrValues(d)
        witness = Witness(**d['witness'])
        result = cls(**d)
        return result._replace(witness=witness)

    def to_str_dict(self):
        return {
        }


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

    def to_str_dict(self):
        return {
            'primary_claim': self.primaryClaim.to_str_dict(),
            'non_revocation_claim': self.nonRevocClaim.to_str_dict() if self.nonRevocClaim else None
        }

    @classmethod
    def from_str_dict(cls, data, n):
        primary = PrimaryClaim.from_str_dict(data['primary_claim'], n)
        nonRevoc = None
        if 'non_revocation_claim' in data and data['non_revocation_claim']:
            nonRevoc = NonRevocationClaim.fromStrDict(data['non_revocation_claim'])

        return cls(primaryClaim=primary, nonRevocClaim=nonRevoc)


class ClaimsPair(dict):
    def __str__(self):
        rtn = list()
        rtn.append('Claims')

        for schema_key, claim_attrs in self.items():
            rtn.append('')
            rtn.append(schema_key.name)
            rtn.append(str(schema_key))
            rtn.append('Attributes:')
            for attr_name, attr_raw_enc in claim_attrs.items():
                rtn.append('    {}: {}'.format(str(attr_name),
                                               str(attr_raw_enc)))

        return os.linesep.join(rtn)


class AttributeInfo(
    namedtuple('AttributeInfo', 'name, schema_seq_no, issuer_did'),
    NamedTupleStrSerializer):
    def __new__(cls, name=None, schema_seq_no=None, issuer_did=None):
        return super(AttributeInfo, cls).__new__(cls, name, schema_seq_no, issuer_did)

    def to_str_dict(self):
        return {
            'name': self.name,
            'schema_seq_no': self.schema_seq_no,
            'issuer_did': self.issuer_did
        }

    @classmethod
    def from_str_dict(cls, d):
        schema_seq_no = int(d['schema_seq_no']) if d['schema_seq_no'] else None
        issuer_did = int(d['issuer_did']) if (('issuer_did' in d) and d['issuer_did']) else None
        name = d['name']
        return AttributeInfo(name, schema_seq_no, issuer_did)


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
                                   'e, v, m, m1, m2, Aprime, revealedAttrs'),
                        NamedTupleStrSerializer):

    def to_str_dict(self):
        return {
            'e': str(crypto_int_to_str(self.e)),
            'v': str(crypto_int_to_str(self.v)),
            'm1': str(crypto_int_to_str(self.m1)),
            'm2': str(crypto_int_to_str(self.m2)),
            'm': {k: str(crypto_int_to_str(v)) for k, v in self.m.items()},
            'revealed_attrs': {k: str(v) for k, v in self.revealedAttrs.items()},
            'a_prime': str(crypto_int_to_str(self.Aprime))
        }

    @classmethod
    def from_str_dict(cls, d, n):
        e = to_crypto_int(d['e'])
        v = to_crypto_int(d['v'])
        m1 = to_crypto_int(d['m1'])
        m2 = to_crypto_int(d['m2'])
        Aprime = to_crypto_int(d['a_prime'], str(n))
        revealedAttrs = {k: to_crypto_int(v) for k, v in d['revealed_attrs'].items()}
        m = {k: to_crypto_int(v) for k, v in d['m'].items()}

        return PrimaryEqualProof(e=e, v=v, m1=m1, m2=m2, m=m, Aprime=Aprime, revealedAttrs=revealedAttrs)


class PrimaryPredicateGEProof(
    namedtuple('PrimaryPredicateGEProof', 'u, r, alpha, mj, T, predicate'),
    NamedTupleStrSerializer):
    @classmethod
    def fromStrDict(cls, d):
        d = fromDictWithStrValues(d)
        predicate = PredicateGE(**d['predicate'])
        result = cls(**d)
        return result._replace(predicate=predicate)

    def to_str_dict(self):
        return {
            'alpha': str(crypto_int_to_str(self.alpha)),
            'mj': str(crypto_int_to_str(self.mj)),
            'u': {k: str(crypto_int_to_str(v)) for k, v in self.u.items()},
            'r': {k: str(crypto_int_to_str(v)) for k, v in self.r.items()},
            't': {k: str(crypto_int_to_str(v)) for k, v in self.T.items()},
            'predicate': self.predicate.to_str_dict()
        }

    @classmethod
    def from_str_dict(cls, d, n):
        alpha = to_crypto_int(d['alpha'])
        mj = to_crypto_int(d['mj'])
        u = {k: to_crypto_int(v) for k, v in d['u'].items()}
        r = {k: to_crypto_int(v) for k, v in d['r'].items()}
        T = {k: to_crypto_int(v, str(n)) for k, v in d['t'].items()}
        predicate = PredicateGE.from_str_dict(d['predicate'])

        return PrimaryPredicateGEProof(alpha=alpha, mj=mj, u=u, r=r, T=T, predicate=predicate)


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
        geProofs = [PrimaryPredicateGEProof.fromStrDict(v) for v in d['geProofs']]
        return PrimaryProof(eqProof=eqProof, geProofs=geProofs)

    def to_str_dict(self):
        return {
            'eq_proof': self.eqProof.to_str_dict(),
            'ge_proofs': [p.to_str_dict() for p in self.geProofs]
        }

    @classmethod
    def from_str_dict(cls, d, n):
        eqProof = PrimaryEqualProof.from_str_dict(d['eq_proof'], n)
        geProofs = [PrimaryPredicateGEProof.from_str_dict(p, n) for p in d['ge_proofs']]

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

    def to_str_dict(self):
        return {
            'primary_proof': self.primaryProof.to_str_dict()
        }

    @classmethod
    def from_str_dict(cls, d, n):
        primaryProof = PrimaryProof.from_str_dict(d['primary_proof'], n)

        return Proof(primaryProof=primaryProof)


class ProofInfo(namedtuple('ProofInfo', 'proof, schema_seq_no, issuer_did'),
                NamedTupleStrSerializer):
    @classmethod
    def fromStrDict(cls, d):
        d = fromDictWithStrValues(d)
        proof = Proof.fromStrDict(d['proof'])
        result = cls(**d)
        return result._replace(proof=proof)

    def to_str_dict(self):
        return {
            'proof': self.proof.to_str_dict(),
            'schema_seq_no': self.schema_seq_no,
            'issuer_did': self.issuer_did
        }

    @classmethod
    def from_str_dict(cls, d, n):
        proof = Proof.from_str_dict(d['proof'], n)
        schema_seq_no = d['schema_seq_no']
        issuer_did = d['issuer_did']

        return ProofInfo(proof=proof, schema_seq_no=schema_seq_no, issuer_did=issuer_did)


class FullProof(namedtuple('FullProof', 'proofs, aggregatedProof, requestedProof'),
                NamedTupleStrSerializer):
    def getCredDefs(self):
        return self.proofs.keys()

    @classmethod
    def fromStrDict(cls, d):
        d = fromDictWithStrValues(d)
        aggregatedProof = AggregatedProof.fromStrDict(d['aggregatedProof'])
        requestedProof = RequestedProof.fromStrDict(d['requestedProof'])
        proofs = {k: ProofInfo.fromStrDict(v) for k, v in d['proofs'].items()}

        return FullProof(aggregatedProof=aggregatedProof, proofs=proofs, requestedProof=requestedProof)

    def to_str_dict(self):
        return {
            'aggregated_proof': self.aggregatedProof.to_str_dict(),
            'proofs': {k: v.to_str_dict() for k, v in self.proofs.items()},
            'requested_proof': self.requestedProof.to_str_dict()
        }

    @classmethod
    def from_str_dict(cls, d, n):
        aggregatedProof = AggregatedProof.from_str_dict(d['aggregated_proof'])
        requestedProof = RequestedProof.from_str_dict(d['requested_proof'])
        proofs = {item[0]: ProofInfo.from_str_dict(item[1], n[i]) for i, item in enumerate(d['proofs'].items())}

        return FullProof(aggregatedProof=aggregatedProof, requestedProof=requestedProof, proofs=proofs)


class AggregatedProof(namedtuple('AggregatedProof', 'cHash, CList'),
                      NamedTupleStrSerializer):
    def to_str_dict(self):
        return {
            'c_hash': str(self.cHash),
            'c_list': [intToArrayBytes(v) for v in self.CList if isCryptoInteger(v)]
        }

    @classmethod
    def from_str_dict(cls, d):
        cHash = int(d['c_hash'])
        CList = [bytesToInt(v) for v in d['c_list']]
        return AggregatedProof(cHash=cHash, CList=CList)


class RequestedProof(namedtuple('RequestedProof', 'revealed_attrs, unrevealed_attrs, self_attested_attrs, predicates'),
                     NamedTupleStrSerializer):
    def __new__(cls, revealed_attrs=None, unrevealed_attrs=None, self_attested_attrs=None, predicates=None):
        return super(RequestedProof, cls).__new__(cls, revealed_attrs or {}, unrevealed_attrs or {},
                                                  self_attested_attrs or {}, predicates or {})

    @classmethod
    def fromStrDict(cls, d):
        revealed_attrs = {k: [v[0], v[1], v[2]] for k, v in d['revealed_attrs'].items()}
        predicates = {k: v for k, v in d['predicates'].items()}
        return RequestedProof(revealed_attrs=revealed_attrs, predicates=predicates)

    def to_str_dict(self):
        return {
            'revealed_attrs': self.revealed_attrs,
            'unrevealed_attrs': self.unrevealed_attrs,
            'self_attested_attrs': self.self_attested_attrs,
            'predicates': self.predicates
        }

    @classmethod
    def from_str_dict(cls, d):
        revealed_attrs = d['revealed_attrs']
        unrevealed_attrs = d['unrevealed_attrs']
        self_attested_attrs = d['self_attested_attrs']
        predicates = d['predicates']
        return RequestedProof(revealed_attrs=revealed_attrs, unrevealed_attrs=unrevealed_attrs,
                              self_attested_attrs=self_attested_attrs, predicates=predicates)


class ClaimAttributeValues(namedtuple('ClaimAttributeValues', 'raw, encoded'),
                      NamedTupleStrSerializer):
    def __new__(cls, raw=None, encoded=None):
        return super(ClaimAttributeValues, cls).__new__(cls, raw, encoded)

    def __str__(self):
        return self.raw

    def to_str_dict(self):
        return [str(self.raw), str(self.encoded)]

    @classmethod
    def from_str_dict(cls, d):
        raw = d[0]
        encoded = int(to_crypto_int(d[1]))
        return ClaimAttributeValues(raw=raw, encoded=encoded)


AvailableClaim = NamedTuple("AvailableClaim", [("name", str),
                                               ("version", str),
                                               ("origin", str)])


class ProofRequest:
    def __init__(self, name, version, nonce, attributes={}, verifiableAttributes={}, predicates={}):
        self.name = name
        self.version = version
        self.nonce = nonce
        self.attributes = attributes
        self.verifiableAttributes = \
            {str(uuid.uuid4()): AttributeInfo(name=a) for a in verifiableAttributes} if \
                isinstance(verifiableAttributes, list) else verifiableAttributes
        self.predicates = {str(uuid.uuid4()): PredicateGE(attrName=p['attrName'], value=p['value']) for p in
                           predicates} if isinstance(predicates, list) else predicates
        self.fulfilledByClaims = []
        self.selfAttestedAttrs = {}
        self.ts = None
        self.seqNo = None
        # TODO _F_ need to add support for predicates on unrevealed attibutes

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    @property
    def toDict(self):
        return {
            "name": self.name,
            "version": self.version,
            "nonce": self.nonce,
            "attributes": self.attributes,
            "verifiableAttributes": self.verifiableAttributes
        }

    def to_str_dict(self):
        return {
            "name": self.name,
            "version": self.version,
            "nonce": str(self.nonce),
            "requested_attrs": {k: v.to_str_dict() for k, v in self.verifiableAttributes.items()},
            "requested_predicates": {k: v.to_str_dict() for k, v in self.predicates.items()}
        }

    @staticmethod
    def from_str_dict(d):
        return ProofRequest(name=d['name'],
                            version=d['version'],
                            nonce=int(d['nonce']),
                            attributes=d['attributes'] if 'attributes' in d else {},
                            verifiableAttributes={k: AttributeInfo.from_str_dict(v) for k, v in
                                                  d['requested_attrs'].items()},
                            predicates={k: PredicateGE.from_str_dict(v) for k, v in d['requested_predicates'].items()})

    @property
    def attributeValues(self):
        return \
            'Attributes:' + '\n    ' + \
            format("\n    ".join(
                ['{}: {}'.format(k, v)
                 for k, v in self.attributes.items()])) + '\n'

    @property
    def verifiableClaimAttributeValues(self):
        return \
            'Verifiable Attributes:' + '\n    ' + \
            format("\n    ".join(
                ['{}'.format(v.name)
                 for k, v in self.verifiableAttributes.items()])) + '\n'

    @property
    def predicateValues(self):
        return \
            'Predicates:' + '\n    ' + \
            format("\n    ".join(
                ['{}'.format(v.attrName)
                 for k, v in self.predicates.items()])) + '\n'

    @property
    def fixedInfo(self):
        return 'Status: Requested' + '\n' + \
               'Name: ' + self.name + '\n' + \
               'Version: ' + self.version + '\n'

    def __str__(self):
        return 'Proof Request\n' + \
               self.fixedInfo + \
               self.attributeValues + \
               self.verifiableClaimAttributeValues
