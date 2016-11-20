from anoncreds.protocol.globals import LARGE_MASTER_SECRET
from anoncreds.protocol.primary.primary_claim_issuer import PrimaryClaimIssuer
from anoncreds.protocol.revocation.accumulators.non_revocation_claim_issuer import NonRevocationClaimIssuer
from anoncreds.protocol.types import SecretKey, PublicKey, SecretData, Attribs, PrimaryClaim, NonRevocationClaim, \
    RevocationPublicKey, RevocationSecretKey, Accumulator, GType, AccumulatorPublicKey, AccumulatorSecretKey, \
    CredentialDefinition
from anoncreds.protocol.utils import get_hash, bytes_to_int
from config.config import cmod


class Issuer:
    def __init__(self, secretData: SecretData):
        self._primaryIssuer = PrimaryClaimIssuer(secretData.secrPrimary)
        self._nonRevocationIssuer = None
        if secretData.secrRevoc:
            self._nonRevocationIssuer = NonRevocationClaimIssuer(secretData.secrRevoc)

    @classmethod
    def genCredDef(cls, name, version, attrNames, type='CL') -> CredentialDefinition:
        return CredentialDefinition(name, version, attrNames, type)

    @classmethod
    def genKeys(cls, credDef, p_prime=None, q_prime=None) -> (PublicKey, SecretKey):
        return PrimaryClaimIssuer.genKeys(credDef, p_prime, q_prime)

    @classmethod
    def genRevocationKeys(cls) -> (RevocationPublicKey, RevocationSecretKey):
        return NonRevocationClaimIssuer.genRevocationKeys()

    @classmethod
    def issueAccumulator(cls, iA, pkR, L) \
            -> (Accumulator, GType, AccumulatorPublicKey, AccumulatorSecretKey):
        return NonRevocationClaimIssuer.issueAccumulator(iA, pkR, L)

    @classmethod
    def genContxt(cls, iA: int, userId: int) -> cmod.integer:
        S = iA | userId
        H = bytes_to_int(get_hash(S))
        return cmod.integer(H % (2 ** LARGE_MASTER_SECRET))

    def issuePrimaryClaim(self, attributes, m2, U) -> PrimaryClaim:
        return self._primaryIssuer.issuePrimaryClaim(attributes, m2, U)

    def issueNonRevocationClaim(self, m2, Ur, i=None) -> NonRevocationClaim:
        if not self._nonRevocationIssuer:
            raise ValueError('Non-revocation keys are not inititialized')
        return self._nonRevocationIssuer.issueNonRevocationClaim(m2, Ur, i)

    def revoke(self, i):
        if not self._nonRevocationIssuer:
            raise ValueError('Non-revocation keys are not inititialized')
        return self._nonRevocationIssuer.revoke(i)

    def __repr__(self):
        return str(self.__dict__)
