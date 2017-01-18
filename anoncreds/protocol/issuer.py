from typing import Dict

from anoncreds.protocol.globals import LARGE_MASTER_SECRET, TYPE_CL
from anoncreds.protocol.primary.primary_claim_issuer import PrimaryClaimIssuer
from anoncreds.protocol.repo.attributes_repo import AttributeRepo
from anoncreds.protocol.revocation.accumulators.non_revocation_claim_issuer import \
    NonRevocationClaimIssuer
from anoncreds.protocol.types import PrimaryClaim, NonRevocationClaim, \
    ClaimDefinition, ID, Claims, ClaimRequest, Attribs, PublicKey, \
    RevocationPublicKey, AccumulatorPublicKey
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
    def issuerId(self):
        return self.wallet.walletId

    async def genClaimDef(self, name, version, attrNames,
                          claimDefType=TYPE_CL) -> ClaimDefinition:
        """
        Generates and submits Claim Definition.

        :param name: claim definition name
        :param version: claim definition version
        :param attrNames: a list of attributes the claim definition contains
        :param claimDefType: a type of the claim definition
        :return: submitted Claim Definition
        """
        claimDef = ClaimDefinition(name, version, attrNames, claimDefType,
                                   self.issuerId)
        return await self.wallet.submitClaimDef(claimDef)

    async def genKeys(self, claimDefId: ID, p_prime=None, q_prime=None) -> (
            PublicKey, RevocationPublicKey):
        """
        Generates and submits keys (both public and secret, primary and
        non-revocation).

        :param claimDefId: The claim definition ID (reference to claim
        definition schema)
        :param p_prime: optional p_prime parameter
        :param q_prime: optional q_prime parameter
        :return: Submitted Public keys (both primary and non-revocation)
        """
        pk, sk = await self._primaryIssuer.genKeys(claimDefId, p_prime, q_prime)
        pkR, skR = await self._nonRevocationIssuer.genRevocationKeys()
        pk = await self.wallet.submitPublicKeys(claimDefId=claimDefId, pk=pk,
                                                pkR=pkR)
        pkR = await self.wallet.submitSecretKeys(claimDefId=claimDefId, sk=sk,
                                                 skR=skR)
        return pk, pkR

    async def issueAccumulator(self, claimDefId: ID, iA,
                               L) -> AccumulatorPublicKey:
        """
        Issues and submits an accumulator used for non-revocation proof.

        :param claimDefId: The claim definition ID (reference to claim
        definition schema)
        :param iA: accumulator ID
        :param L: maximum number of claims within accumulator.
        :return: Submitted accumulator public key
        """
        accum, tails, accPK, accSK = await self._nonRevocationIssuer.issueAccumulator(
            claimDefId, iA, L)
        accPK = await self.wallet.submitAccumPublic(claimDefId=claimDefId,
                                                    accumPK=accPK,
                                                    accum=accum, tails=tails)
        await self.wallet.submitAccumSecret(claimDefId=claimDefId,
                                            accumSK=accSK)
        return accPK

    async def revoke(self, claimDefId: ID, i):
        """
        Performs revocation of a Claim.

        :param claimDefId: The claim definition ID (reference to claim
        definition schema)
        :param i: claim's sequence number within accumulator
        """
        acc, ts = await self._nonRevocationIssuer.revoke(claimDefId, i)
        await self.wallet.submitAccumUpdate(claimDefId=claimDefId, accum=acc,
                                            timestampMs=ts)

    async def issueClaim(self, claimDefId: ID, claimRequest: ClaimRequest,
                         iA=None,
                         i=None) -> Claims:
        """
        Issue a claim for the given user and claim definition.

        :param claimDefId: The claim definition ID (reference to claim
        definition schema)
        :param claimRequest: A claim request containing prover ID and
        prover-generated values
        :param iA: accumulator ID
        :param i: claim's sequence number within accumulator
        :return: The claim (both primary and non-revocation)
        """

        claimDefKey = (await self.wallet.getClaimDef(claimDefId)).getKey()
        attributes = self._attrRepo.getAttributes(claimDefKey,
                                                  claimRequest.userId)
        iA = iA if iA else (await self.wallet.getAccumulator(claimDefId)).iA

        await self._genContxt(claimDefId, iA, claimRequest.userId)

        c1 = await self._issuePrimaryClaim(claimDefId, attributes,
                                           claimRequest.U)
        c2 = await self._issueNonRevocationClaim(claimDefId, claimRequest.Ur,
                                                 iA,
                                                 i) if claimRequest.Ur else None
        return Claims(primaryClaim=c1, nonRevocClaim=c2)

    async def issueClaims(self, allClaimRequest: Dict[ID, ClaimRequest]) -> \
            Dict[ID, Claims]:
        """
        Issue claims for the given users and claim definitions.

        :param allClaimRequest: a map of claim definition ID to a claim
        request containing prover ID and prover-generated values
        :return: The claims (both primary and non-revocation)
        """
        res = {}
        for claimDefId, claimReq in allClaimRequest.items():
            res[claimDefId] = await self.issueClaim(claimDefId, claimReq)
        return res

    #
    # PRIVATE
    #

    async def _genContxt(self, claimDefId: ID, iA, userId):
        iA = strToInt(str(iA))
        userId = strToInt(str(userId))
        S = iA | userId
        H = get_hash_as_int(S)
        m2 = cmod.integer(H % (2 ** LARGE_MASTER_SECRET))
        await self.wallet.submitContextAttr(claimDefId, m2)
        return m2

    async def _issuePrimaryClaim(self, claimDefId: ID, attributes: Attribs,
                                 U) -> PrimaryClaim:
        return await self._primaryIssuer.issuePrimaryClaim(claimDefId,
                                                           attributes, U)

    async def _issueNonRevocationClaim(self, claimDefId: ID, Ur, iA=None,
                                       i=None) -> NonRevocationClaim:
        claim, accum, ts = await self._nonRevocationIssuer.issueNonRevocationClaim(
            claimDefId, Ur, iA, i)
        await self.wallet.submitAccumUpdate(claimDefId=claimDefId, accum=accum,
                                            timestampMs=ts)
        return claim

    def __repr__(self):
        return str(self.__dict__)
