from typing import Dict

from anoncreds.protocol.globals import LARGE_MASTER_SECRET
from anoncreds.protocol.primary.primary_claim_issuer import PrimaryClaimIssuer
from anoncreds.protocol.repo.attributes_repo import AttributeRepo
from anoncreds.protocol.revocation.accumulators.non_revocation_claim_issuer import \
    NonRevocationClaimIssuer
from anoncreds.protocol.types import PrimaryClaim, NonRevocationClaim, \
    Schema, ID, Claims, ClaimRequest, Attribs, PublicKey, \
    RevocationPublicKey, AccumulatorPublicKey, ClaimAttributeValues
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

    def isSchemaExists(self, schemaKey):
        return self.wallet._schemasByKey.get(schemaKey)

    async def genSchema(self, name, version, attrNames) -> Schema:
        """
        Generates and submits Schema.

        :param name: schema name
        :param version: schema version
        :param attrNames: a list of attributes the schema contains
        :return: submitted Schema
        """
        schema = Schema(name, version, attrNames, self.issuerId)
        return await self.wallet.submitSchema(schema)

    async def genKeys(self, schemaId: ID, p_prime=None, q_prime=None) -> (
            PublicKey, RevocationPublicKey):
        """
        Generates and submits keys (both public and secret, primary and
        non-revocation).

        :param schemaId: The schema ID (reference to claim
        definition schema)
        :param p_prime: optional p_prime parameter
        :param q_prime: optional q_prime parameter
        :return: Submitted Public keys (both primary and non-revocation)
        """
        pk, sk = await self._primaryIssuer.genKeys(schemaId, p_prime, q_prime)
        pkR, skR = await self._nonRevocationIssuer.genRevocationKeys()
        pk = await self.wallet.submitPublicKeys(schemaId=schemaId, pk=pk,
                                                pkR=pkR)
        pkR = await self.wallet.submitSecretKeys(schemaId=schemaId, sk=sk,
                                                 skR=skR)
        return pk, pkR

    async def issueAccumulator(self, schemaId: ID, iA,
                               L) -> AccumulatorPublicKey:
        """
        Issues and submits an accumulator used for non-revocation proof.

        :param schemaId: The schema ID (reference to claim
        definition schema)
        :param iA: accumulator ID
        :param L: maximum number of claims within accumulator.
        :return: Submitted accumulator public key
        """
        accum, tails, accPK, accSK = await self._nonRevocationIssuer.issueAccumulator(
            schemaId, iA, L)
        accPK = await self.wallet.submitAccumPublic(schemaId=schemaId,
                                                    accumPK=accPK,
                                                    accum=accum, tails=tails)
        await self.wallet.submitAccumSecret(schemaId=schemaId,
                                            accumSK=accSK)
        return accPK

    async def revoke(self, schemaId: ID, i):
        """
        Performs revocation of a Claim.

        :param schemaId: The schema ID (reference to claim
        definition schema)
        :param i: claim's sequence number within accumulator
        """
        acc, ts = await self._nonRevocationIssuer.revoke(schemaId, i)
        await self.wallet.submitAccumUpdate(schemaId=schemaId, accum=acc,
                                            timestampMs=ts)

    async def issueClaim(self, schemaId: ID, claimRequest: ClaimRequest,
                         iA=None,
                         i=None) -> (Claims, Dict[str, ClaimAttributeValues]):
        """
        Issue a claim for the given user and schema.

        :param schemaId: The schema ID (reference to claim
        definition schema)
        :param claimRequest: A claim request containing prover ID and
        prover-generated values
        :param iA: accumulator ID
        :param i: claim's sequence number within accumulator
        :return: The claim (both primary and non-revocation)
        """

        schemaKey = (await self.wallet.getSchema(schemaId)).getKey()
        attributes = self._attrRepo.getAttributes(schemaKey,
                                                  claimRequest.userId)

        # TODO re-enable when revocation registry is implemented
        # iA = iA if iA else (await self.wallet.getAccumulator(schemaId)).iA

        # TODO this has un-obvious side-effects
        await self._genContxt(schemaId, iA, claimRequest.userId)

        (c1, claim) = await self._issuePrimaryClaim(schemaId, attributes,
                                           claimRequest.U)
        # TODO re-enable when revocation registry is fully implemented
        c2 = await self._issueNonRevocationClaim(schemaId, claimRequest.Ur,
                                                 iA,
                                                 i) if claimRequest.Ur else None

        signature = Claims(primaryClaim=c1, nonRevocClaim=c2)

        return (signature, claim)

    async def issueClaims(self, allClaimRequest: Dict[ID, ClaimRequest]) -> \
            Dict[ID, Claims]:
        """
        Issue claims for the given users and schemas.

        :param allClaimRequest: a map of schema ID to a claim
        request containing prover ID and prover-generated values
        :return: The claims (both primary and non-revocation)
        """
        res = {}
        for schemaId, claimReq in allClaimRequest.items():
            res[schemaId] = await self.issueClaim(schemaId, claimReq)
        return res

    #
    # PRIVATE
    #

    async def _genContxt(self, schemaId: ID, iA, userId):
        iA = strToInt(str(iA))
        userId = strToInt(str(userId))
        S = iA | userId
        H = get_hash_as_int(S)
        m2 = cmod.integer(H % (2 ** LARGE_MASTER_SECRET))
        await self.wallet.submitContextAttr(schemaId, m2)
        return m2

    async def _issuePrimaryClaim(self, schemaId: ID, attributes: Attribs,
                                 U) -> (PrimaryClaim, Dict[str, ClaimAttributeValues]):
        return await self._primaryIssuer.issuePrimaryClaim(schemaId,
                                                           attributes, U)

    async def _issueNonRevocationClaim(self, schemaId: ID, Ur, iA=None,
                                       i=None) -> NonRevocationClaim:
        claim, accum, ts = await self._nonRevocationIssuer.issueNonRevocationClaim(
            schemaId, Ur, iA, i)
        await self.wallet.submitAccumUpdate(schemaId=schemaId, accum=accum,
                                            timestampMs=ts)
        return claim

    def __repr__(self):
        return str(self.__dict__)
