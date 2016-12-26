from typing import Dict

from anoncreds.protocol.globals import LARGE_MASTER_SECRET, TYPE_CL
from anoncreds.protocol.primary.primary_claim_issuer import PrimaryClaimIssuer
from anoncreds.protocol.repo.attributes_repo import AttributeRepo
from anoncreds.protocol.revocation.accumulators.non_revocation_claim_issuer import \
    NonRevocationClaimIssuer
from anoncreds.protocol.types import PrimaryClaim, NonRevocationClaim, \
    ClaimDefinition, ID, Claims, ClaimRequest, Attribs, PublicKey, \
    RevocationPublicKey
from anoncreds.protocol.utils import strToInt, get_hash_as_int
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

    async def genClaimDef(self, name, version, attrNames,
                          type=TYPE_CL) -> ClaimDefinition:
        claimDef = ClaimDefinition(name, version, attrNames, type,
                                   self.wallet.id)
        return await self.wallet.submitClaimDef(claimDef)

    async def genKeys(self, id: ID, p_prime=None, q_prime=None) -> (
            PublicKey, RevocationPublicKey):
        pk, sk = await self._primaryIssuer.genKeys(id, p_prime, q_prime)
        pkR, skR = await self._nonRevocationIssuer.genRevocationKeys()
        pk = await self.wallet.submitPublicKeys(id=id, pk=pk, pkR=pkR)
        pkR = await self.wallet.submitSecretKeys(id=id, sk=sk, skR=skR)
        return (pk, pkR)

    async def issueAccumulator(self, id: ID, iA, L):
        accum, tails, accPK, accSK = await self._nonRevocationIssuer.issueAccumulator(
            id, iA, L)
        accPK = await self.wallet.submitAccumPublic(id=id, accumPK=accPK,
                                                    accum=accum, tails=tails)
        await self.wallet.submitAccumSecret(id=id, accumSK=accSK)
        return accPK

    async def revoke(self, id: ID, i):
        acc, ts = await self._nonRevocationIssuer.revoke(id, i)
        await self.wallet.submitAccumUpdate(id=id, accum=acc, timestampMs=ts)

    async def issueClaim(self, id: ID, claimRequest: ClaimRequest, iA=None,
                         i=None) -> Claims:
        claimDefKey = (await self.wallet.getClaimDef(id)).getKey()
        attributes = self._attrRepo.getAttributes(claimDefKey,
                                                  claimRequest.userId)
        iA = iA if iA else (await self.wallet.getAccumulator(id)).iA

        await self._genContxt(id, iA, claimRequest.userId)

        c1 = await self._issuePrimaryClaim(id, attributes, claimRequest.U)
        c2 = await self._issueNonRevocationClaim(id, claimRequest.Ur, iA,
                                                 i) if claimRequest.Ur else None
        return Claims(primaryClaim=c1, nonRevocClaim=c2)

    async def issueClaims(self, allClaimRequest: Dict[ID, ClaimRequest]) -> \
            Dict[ID, Claims]:
        res = {}
        for id, claimReq in allClaimRequest.items():
            res[id] = await self.issueClaim(id, claimReq)
        return res

    #
    # PRIVATE
    #

    async def _genContxt(self, id: ID, iA, userId):
        iA = strToInt(str(iA))
        userId = strToInt(str(userId))
        S = iA | userId
        H = get_hash_as_int(S)
        m2 = cmod.integer(H % (2 ** LARGE_MASTER_SECRET))
        await self.wallet.submitContextAttr(id, m2)
        return m2

    async def _issuePrimaryClaim(self, id: ID, attributes: Attribs,
                                 U) -> PrimaryClaim:
        return await self._primaryIssuer.issuePrimaryClaim(id, attributes, U)

    async def _issueNonRevocationClaim(self, id: ID, Ur, iA=None,
                                       i=None) -> NonRevocationClaim:
        claim, accum, ts = await self._nonRevocationIssuer.issueNonRevocationClaim(
            id, Ur, iA, i)
        await self.wallet.submitAccumUpdate(id=id, accum=accum, timestampMs=ts)
        return claim

    def __repr__(self):
        return str(self.__dict__)
