from typing import Any

from anoncreds.protocol.globals import LARGE_MASTER_SECRET, TYPE_CL
from anoncreds.protocol.primary.primary_claim_issuer import PrimaryClaimIssuer
from anoncreds.protocol.repo.attributes_repo import AttributeRepo
from anoncreds.protocol.revocation.accumulators.non_revocation_claim_issuer import NonRevocationClaimIssuer
from anoncreds.protocol.types import PrimaryClaim, NonRevocationClaim, \
    ClaimDefinition, ID, Claims
from anoncreds.protocol.utils import get_hash, bytes_to_int
from anoncreds.protocol.wallet.issuer_wallet import IssuerWallet

from config.config import cmod


class Issuer:
    def __init__(self, wallet: IssuerWallet, attrRepo: AttributeRepo):
        self.wallet = wallet
        self._attrRepo = attrRepo
        self._primaryIssuer = PrimaryClaimIssuer(wallet)
        self._nonRevocationIssuer = NonRevocationClaimIssuer(wallet)

    #
    # PUBLIC
    #

    @property
    def id(self):
        return self.wallet.id

    def genClaimDef(self, name, version, attrNames, type=TYPE_CL) -> ClaimDefinition:
        claimDef = ClaimDefinition(name, version, attrNames, type, self.wallet.id)
        self.wallet.submitClaimDef(claimDef)
        return claimDef

    def genKeys(self, id: ID, p_prime=None, q_prime=None):
        pk, sk = self._primaryIssuer.genKeys(id, p_prime, q_prime)
        pkR, skR = self._nonRevocationIssuer.genRevocationKeys()
        self.wallet.submitPublicKeys(id=id, pk=pk, pkR=pkR)
        self.wallet.submitSecretKeys(id=id, sk=sk, skR=skR)

    def issueAccumulator(self, id: ID, iA, L):
        accum, tails, accPK, accSK = self._nonRevocationIssuer.issueAccumulator(id, iA, L)
        self.wallet.submitAccumPublic(id=id, accumPK=accPK, accum=accum, tails=tails)
        self.wallet.submitAccumSecret(id=id, accumSK=accSK)

    def revoke(self, id: ID, i):
        acc, ts = self._nonRevocationIssuer.revoke(id, i)
        self.wallet.submitAccumUpdate(id=id, accum=acc, timestampMs=ts)

    def issueClaims(self, id: ID, userId, U, Ur=None, iA=None, i=None) -> (Claims, Any):
        claimDefKey = self.wallet.getClaimDef(id).getKey()
        attributes = self._attrRepo.getAttributes(claimDefKey, userId).encoded()
        iA = iA if iA else self.wallet.getAccumulator(id).iA

        m2 = self._genContxt(id, iA, userId)
        c1 = self._issuePrimaryClaim(id, attributes, U)
        c2 = self._issueNonRevocationClaim(id, Ur, i) if Ur else None
        return (Claims(primaryClaim=c1, nonRevocClaim=c2), m2)

    #
    # PRIVATE
    #

    def _genContxt(self, id: ID, iA, userId):
        S = int(iA) | int(userId)
        H = bytes_to_int(get_hash(S))
        m2 = cmod.integer(H % (2 ** LARGE_MASTER_SECRET))
        self.wallet.submitContextAttr(id, m2)
        return m2

    def _issuePrimaryClaim(self, id: ID, attributes, U) -> PrimaryClaim:
        return self._primaryIssuer.issuePrimaryClaim(id, attributes, U)

    def _issueNonRevocationClaim(self, id: ID, Ur, i=None) -> NonRevocationClaim:
        claim, accum, ts = self._nonRevocationIssuer.issueNonRevocationClaim(id, Ur, i)
        self.wallet.submitAccumUpdate(id=id, accum=accum, timestampMs=ts)
        return claim

    def __repr__(self):
        return str(self.__dict__)
