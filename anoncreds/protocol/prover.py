from functools import reduce
from typing import Dict, Sequence, Any

from anoncreds.protocol.globals import LARGE_MASTER_SECRET, LARGE_M2_TILDE
from anoncreds.protocol.primary.primary_proof_builder import \
    PrimaryClaimInitializer, PrimaryProofBuilder
from anoncreds.protocol.revocation.accumulators.non_revocation_proof_builder import \
    NonRevocationClaimInitializer, \
    NonRevocationProofBuilder
from anoncreds.protocol.types import PrimaryClaim, NonRevocationClaim, Proof, \
    InitProof, ProofInput, ProofClaims, \
    FullProof, \
    Schema, ID, SchemaKey, ClaimRequest, Claims
from anoncreds.protocol.utils import get_hash_as_int
from anoncreds.protocol.wallet.prover_wallet import ProverWallet
from config.config import cmod


class Prover:
    def __init__(self, wallet: ProverWallet):
        self.wallet = wallet

        self._primaryClaimInitializer = PrimaryClaimInitializer(wallet)
        self._nonRevocClaimInitializer = NonRevocationClaimInitializer(wallet)

        self._primaryProofBuilder = PrimaryProofBuilder(wallet)
        self._nonRevocProofBuilder = NonRevocationProofBuilder(wallet)

    #
    # PUBLIC
    #

    @property
    def proverId(self):
        return self.wallet.walletId

    async def createClaimRequest(self, schemaId: ID, proverId=None,
                                 reqNonRevoc=True) -> ClaimRequest:
        """
        Creates a claim request to the issuer.

        :param schemaId: The schema ID (reference to claim
        definition schema)
        :param proverId: a prover ID request a claim for (if None then
        the current prover default ID is used)
        :param reqNonRevoc: whether to request non-revocation claim
        :return: Claim Request
        """
        await self._genMasterSecret(schemaId)
        U = await self._genU(schemaId)
        Ur = None if not reqNonRevoc else await self._genUr(schemaId)
        proverId = proverId if proverId else self.proverId
        return ClaimRequest(userId=proverId, U=U, Ur=Ur)

    async def createClaimRequests(self, schemaIds: Sequence[ID],
                                  proverId=None,
                                  reqNonRevoc=True) -> Dict[ID, ClaimRequest]:
        """
        Creates a claim request to the issuer.

        :param schemaIds: The schema IDs (references to claim
        definition schema)
        :param proverId: a prover ID request a claim for (if None then
        the current prover default ID is used)
        :param reqNonRevoc: whether to request non-revocation claim
        :return: a dictionary of Claim Requests for each Schema.
        """
        res = {}
        for schemaId in schemaIds:
            res[schemaId] = await self.createClaimRequest(schemaId,
                                                          proverId,
                                                          reqNonRevoc)
        return res

    async def processClaim(self, schemaId: ID, claims: Claims):
        """
        Processes and saves a received Claim for the given Schema.

        :param schemaId: The schema ID (reference to claim
        definition schema)
        :param claims: claims to be processed and saved
        """
        await self.wallet.submitContextAttr(schemaId, claims.primaryClaim.m2)
        await self._initPrimaryClaim(schemaId, claims.primaryClaim)
        if claims.nonRevocClaim:
            await self._initNonRevocationClaim(schemaId, claims.nonRevocClaim)

    async def processClaims(self, allClaims: Dict[ID, Claims]):
        """
        Processes and saves received Claims.

        :param claims: claims to be processed and saved for each claim
        definition.
        """
        res = []
        for schemaId, claims in allClaims.items():
            res.append(await self.processClaim(schemaId, claims))
        return res

    async def presentProof(self, proofInput: ProofInput, nonce) -> (
            FullProof, Dict[str, Any]):
        """
        Presents a proof to the verifier.

        :param proofInput: description of a proof to be presented (revealed
        attributes, predicates, timestamps for non-revocation)
        :param nonce: verifier's nonce
        :return: a proof (both primary and non-revocation)
        """
        claims, revealedAttrsWithValues = await self._findClaims(proofInput)
        proof = await self._prepareProof(claims, nonce)
        return proof, revealedAttrsWithValues

    #
    # REQUEST CLAIMS
    #

    async def _genMasterSecret(self, schemaId: ID):
        ms = cmod.integer(cmod.randomBits(LARGE_MASTER_SECRET))
        await self.wallet.submitMasterSecret(schemaId=schemaId, ms=ms)

    async def _genU(self, schemaId: ID):
        claimInitData = await self._primaryClaimInitializer.genClaimInitData(
            schemaId)
        await self.wallet.submitPrimaryClaimInitData(schemaId=schemaId,
                                                     claimInitData=claimInitData)
        return claimInitData.U

    async def _genUr(self, schemaId: ID):
        claimInitData = await self._nonRevocClaimInitializer.genClaimInitData(
            schemaId)
        await self.wallet.submitNonRevocClaimInitData(schemaId=schemaId,
                                                      claimInitData=claimInitData)
        return claimInitData.U

    async def _initPrimaryClaim(self, schemaId: ID, claim: PrimaryClaim):
        claim = await self._primaryClaimInitializer.preparePrimaryClaim(
            schemaId,
            claim)
        await self.wallet.submitPrimaryClaim(schemaId=schemaId, claim=claim)

    async def _initNonRevocationClaim(self, schemaId: ID,
                                      claim: NonRevocationClaim):
        claim = await self._nonRevocClaimInitializer.initNonRevocationClaim(
            schemaId,
            claim)
        await self.wallet.submitNonRevocClaim(schemaId=schemaId,
                                              claim=claim)

    #
    # PRESENT PROOF
    #

    async def _findClaims(self, proofInput: ProofInput) -> (
            Dict[SchemaKey, ProofClaims], Dict[str, Any]):
        revealedAttrs, predicates = set(proofInput.revealedAttrs), set(
            proofInput.predicates)

        proofClaims = {}
        foundRevealedAttrs = set()
        foundPredicates = set()
        revealedAttrsWithValues = {}

        allClaims = await self.wallet.getAllClaims()
        for schemaKey, claim in allClaims.items():
            revealedAttrsForClaim = []
            predicatesForClaim = []

            for revealedAttr in revealedAttrs:
                if revealedAttr in claim.primaryClaim.encodedAttrs:
                    revealedAttrsForClaim.append(revealedAttr)
                    foundRevealedAttrs.add(revealedAttr)
                    revealedAttrsWithValues[revealedAttr] = \
                        claim.primaryClaim.encodedAttrs[revealedAttr]

            for predicate in predicates:
                if predicate.attrName in claim.primaryClaim.encodedAttrs:
                    predicatesForClaim.append(predicate)
                    foundPredicates.add(predicate)

            if revealedAttrsForClaim or predicatesForClaim:
                proofClaims[schemaKey] = ProofClaims(claim,
                                                      revealedAttrsForClaim,
                                                      predicatesForClaim)

        if foundRevealedAttrs != revealedAttrs:
            raise ValueError(
                "A claim isn't found for the following attributes: {}",
                revealedAttrs - foundRevealedAttrs)
        if foundPredicates != predicates:
            raise ValueError(
                "A claim isn't found for the following predicates: {}",
                predicates - foundPredicates)

        return proofClaims, revealedAttrsWithValues

    async def _prepareProof(self, claims: Dict[SchemaKey, ProofClaims],
                            nonce) -> FullProof:
        m1Tilde = cmod.integer(cmod.randomBits(LARGE_M2_TILDE))
        initProofs = {}
        CList = []
        TauList = []

        # 1. init proofs
        for schemaKey, val in claims.items():
            c1, c2, revealedAttrs, predicates = val.claims.primaryClaim, val.claims.nonRevocClaim, val.revealedAttrs, val.predicates

            nonRevocInitProof = None
            if c2:
                nonRevocInitProof = await self._nonRevocProofBuilder.initProof(
                    schemaKey, c2)
                CList += nonRevocInitProof.asCList()
                TauList += nonRevocInitProof.asTauList()

            primaryInitProof = None
            if c1:
                m2Tilde = cmod.integer(int(
                    nonRevocInitProof.TauListParams.m2)) if nonRevocInitProof else None
                primaryInitProof = await self._primaryProofBuilder.initProof(
                    schemaKey, c1, revealedAttrs, predicates,
                    m1Tilde, m2Tilde)
                CList += primaryInitProof.asCList()
                TauList += primaryInitProof.asTauList()

            initProof = InitProof(nonRevocInitProof, primaryInitProof)
            initProofs[schemaKey] = initProof

        # 2. hash
        cH = self._get_hash(CList, TauList, nonce)

        # 3. finalize proofs
        proofs = []
        schemaKeys = []
        for schemaKey, initProof in initProofs.items():
            schemaKeys.append(schemaKey)
            nonRevocProof = None
            if initProof.nonRevocInitProof:
                nonRevocProof = await self._nonRevocProofBuilder.finalizeProof(
                    schemaKey, cH, initProof.nonRevocInitProof)
            primaryProof = await self._primaryProofBuilder.finalizeProof(
                schemaKey, cH, initProof.primaryInitProof)
            proofs.append(Proof(primaryProof, nonRevocProof))

        return FullProof(cH, schemaKeys, proofs, CList)

    async def _getCList(self, initProofs: Dict[Schema, InitProof]):
        CList = []
        for initProof in initProofs.values():
            CList += await initProof.nonRevocInitProof.asCList()
            CList += await initProof.primaryInitProof.asCList()
            return CList

    async def _getTauList(self, initProofs: Dict[Schema, InitProof]):
        TauList = []
        for initProof in initProofs.values():
            TauList += await initProof.nonRevocInitProof.asTauList()
            TauList += await initProof.primaryInitProof.asTauList()
        return TauList

    def _get_hash(self, CList, TauList, nonce):
        return get_hash_as_int(nonce,
                               *reduce(lambda x, y: x + y, [TauList, CList]))
