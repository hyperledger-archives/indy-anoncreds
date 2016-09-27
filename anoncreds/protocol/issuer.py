from charm.core.math.integer import integer

from anoncreds.protocol.globals import LARGE_MASTER_SECRET
from anoncreds.protocol.primary_claim_issuer import PrimaryClaimIssuer
from anoncreds.protocol.revocation.accumulators.non_revocation_claim_issuer import NonRevocationClaimIssuer
from anoncreds.protocol.types import SecretKey, PublicKey, SecretData, Attribs, PrimaryClaim, NonRevocationClaim, \
    RevocationPublicKey, RevocationSecretKey, Accumulator, GType, AccumulatorPublicKey, AccumulatorSecretKey
from anoncreds.protocol.utils import get_hash, bytes_to_int


class Issuer:
    def __init__(self, id: int, secretData: SecretData):
        self.id = id
        self._nonRevocationIssuer = NonRevocationClaimIssuer(secretData)
        self._primaryIssuer = PrimaryClaimIssuer(secretData)

    @classmethod
    def genKeys(cls, attrNames, p_prime=None, q_prime=None) -> (PublicKey, SecretKey):
        return PrimaryClaimIssuer.genKeys(attrNames, p_prime, q_prime)

    @classmethod
    def genRevocationKeys(cls) -> (RevocationPublicKey, RevocationSecretKey):
        return NonRevocationClaimIssuer.genRevocationKeys()

    @classmethod
    def issueAccumulator(cls, iA, pkR, L) \
            -> (Accumulator, GType, AccumulatorPublicKey, AccumulatorSecretKey):
        return NonRevocationClaimIssuer.issueAccumulator(iA, pkR, L)

    @classmethod
    def genContxt(cls, iA: int, userId: int) -> integer:
        S = iA | userId
        H = bytes_to_int(get_hash(S))
        return integer(H % (2 ** LARGE_MASTER_SECRET))

    def encodeAttrs(self, attrs: Attribs):
        return attrs.encoded()

    def issuePrimaryClaim(self, attributes, m2, U) -> PrimaryClaim:
        return self._primaryIssuer.issuePrimaryClaim(attributes, m2, U)

    def issueNonRevocationClaim(self, m2, Ur, i=None) -> NonRevocationClaim:
        return self._nonRevocationIssuer.issueNonRevocationClaim(m2, Ur, i)

    def revoke(self, i):
        return self._nonRevocationIssuer.revoke(i)

    def __repr__(self):
        return str(self.__dict__)
