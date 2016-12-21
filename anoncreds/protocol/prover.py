from functools import reduce
from typing import Dict, Sequence, Any

from anoncreds.protocol.globals import LARGE_MASTER_SECRET, LARGE_M2_TILDE
from anoncreds.protocol.primary.primary_proof_builder import PrimaryClaimInitializer, PrimaryProofBuilder
from anoncreds.protocol.revocation.accumulators.non_revocation_proof_builder import NonRevocationClaimInitializer, \
    NonRevocationProofBuilder
from anoncreds.protocol.types import PrimaryClaim, NonRevocationClaim, Proof, InitProof, ProofInput, ProofClaims, \
    FullProof, \
    ClaimDefinition, ID, ClaimDefinitionKey, ClaimRequest, Claims
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
    def id(self):
        return self.wallet.id

    async def createClaimRequest(self, id: ID, proverId=None, reqNonRevoc=True) -> ClaimRequest:
        await self._genMasterSecret(id)
        U = await self._genU(id)
        Ur = None if not reqNonRevoc else await self._genUr(id)
        proverId = proverId if proverId else self.id
        return ClaimRequest(userId=proverId, U=U, Ur=Ur)

    async def createClaimRequests(self, ids: Sequence[ID], proverId=None, reqNonRevoc=True) -> Dict[ID, ClaimRequest]:
        res = {}
        for id in ids:
            res[id] = await self.createClaimRequest(id, proverId, reqNonRevoc)
        return res

    async def processClaim(self, id: ID, claims: Claims):
        await self.wallet.submitContextAttr(id, claims.primaryClaim.m2)
        await self._initPrimaryClaim(id, claims.primaryClaim)
        if claims.nonRevocClaim:
            await self._initNonRevocationClaim(id, claims.nonRevocClaim)

    async def processClaims(self, allClaims: Dict[ID, Claims]):
        res = []
        for id, claims in allClaims.items():
            res.append(await self.processClaim(id, claims))
        return res

    async def presentProof(self, proofInput: ProofInput, nonce) -> (FullProof, Dict[str, Any]):
        claims, revealedAttrsWithValues = await self._findClaims(proofInput)
        proof = await self._prepareProof(claims, nonce)
        return (proof, revealedAttrsWithValues)

    #
    # REQUEST CLAIMS
    #

    async def _genMasterSecret(self, id: ID):
        ms = cmod.integer(cmod.randomBits(LARGE_MASTER_SECRET))
        await self.wallet.submitMasterSecret(id=id, ms=ms)

    async def _genU(self, id: ID):
        claimInitData = await self._primaryClaimInitializer.genClaimInitData(id)
        await self.wallet.submitPrimaryClaimInitData(id=id, claimInitData=claimInitData)
        return claimInitData.U

    async def _genUr(self, id: ID):
        claimInitData = await self._nonRevocClaimInitializer.genClaimInitData(id)
        await self.wallet.submitNonRevocClaimInitData(id=id, claimInitData=claimInitData)
        return claimInitData.U

    async def _initPrimaryClaim(self, id: ID, claim: PrimaryClaim):
        claim = await self._primaryClaimInitializer.preparePrimaryClaim(id, claim)
        await self.wallet.submitPrimaryClaim(id=id, claim=claim)

    async def _initNonRevocationClaim(self, id: ID, claim: NonRevocationClaim):
        claim = await self._nonRevocClaimInitializer.initNonRevocationClaim(id, claim)
        await self.wallet.submitNonRevocClaim(id=id, claim=claim)

    #
    # PRESENT PROOF
    #

    async def _findClaims(self, proofInput: ProofInput) -> (Dict[ClaimDefinitionKey, ProofClaims], Dict[str, Any]):
        revealedAttrs, predicates = set(proofInput.revealedAttrs), set(proofInput.predicates)

        proofClaims = {}
        foundRevealedAttrs = set()
        foundPredicates = set()
        revealedAttrsWithValues = {}

        allClaims = await self.wallet.getAllClaims()
        for credDefKey, claim in allClaims.items():
            revealedAttrsForClaim = []
            predicatesForClaim = []

            for revealedAttr in revealedAttrs:
                if revealedAttr in claim.primaryClaim.encodedAttrs:
                    revealedAttrsForClaim.append(revealedAttr)
                    foundRevealedAttrs.add(revealedAttr)
                    revealedAttrsWithValues[revealedAttr] = claim.primaryClaim.encodedAttrs[revealedAttr]

            for predicate in predicates:
                if predicate.attrName in claim.primaryClaim.encodedAttrs:
                    predicatesForClaim.append(predicate)
                    foundPredicates.add(predicate)

            if revealedAttrsForClaim or predicatesForClaim:
                proofClaims[credDefKey] = ProofClaims(claim, revealedAttrsForClaim, predicatesForClaim)

        if foundRevealedAttrs != revealedAttrs:
            raise ValueError("A claim isn't found for the following attributes: {}", revealedAttrs - foundRevealedAttrs)
        if foundPredicates != predicates:
            raise ValueError("A claim isn't found for the following predicates: {}", predicates - foundPredicates)

        return (proofClaims, revealedAttrsWithValues)

    async def _prepareProof(self, claims: Dict[ClaimDefinitionKey, ProofClaims], nonce) -> FullProof:
        m1Tilde = cmod.integer(cmod.randomBits(LARGE_M2_TILDE))
        initProofs = {}
        CList = []
        TauList = []

        # 1. init proofs
        for claimDefKey, val in claims.items():
            c1, c2, revealedAttrs, predicates = val.claims.primaryClaim, val.claims.nonRevocClaim, val.revealedAttrs, val.predicates

            nonRevocInitProof = None
            if c2:
                nonRevocInitProof = await self._nonRevocProofBuilder.initProof(claimDefKey, c2)
                CList += nonRevocInitProof.asCList()
                TauList += nonRevocInitProof.asTauList()

            primaryInitProof = None
            if c1:
                m2Tilde = cmod.integer(int(nonRevocInitProof.TauListParams.m2)) if nonRevocInitProof else None
                primaryInitProof = await self._primaryProofBuilder.initProof(claimDefKey, c1, revealedAttrs, predicates,
                                                                       m1Tilde, m2Tilde)
                CList += primaryInitProof.asCList()
                TauList += primaryInitProof.asTauList()

            initProof = InitProof(nonRevocInitProof, primaryInitProof)
            initProofs[claimDefKey] = initProof

        # 2. hash
        cH = self._get_hash(CList, TauList, nonce)

        # 3. finalize proofs
        proofs = []
        claimDefKeys = []
        for claimDefKey, initProof in initProofs.items():
            claimDefKeys.append(claimDefKey)
            nonRevocProof = None
            if initProof.nonRevocInitProof:
                nonRevocProof = await self._nonRevocProofBuilder.finalizeProof(claimDefKey, cH, initProof.nonRevocInitProof)
            primaryProof = await self._primaryProofBuilder.finalizeProof(claimDefKey, cH, initProof.primaryInitProof)
            proofs.append(Proof(primaryProof, nonRevocProof))

        return FullProof(cH, claimDefKeys, proofs, CList)

    async def _getCList(self, initProofs: Dict[ClaimDefinition, InitProof]):
        CList = []
        for initProof in initProofs.values():
            CList += await initProof.nonRevocInitProof.asCList()
            CList += await initProof.primaryInitProof.asCList()
            return CList

    async def _getTauList(self, initProofs: Dict[ClaimDefinition, InitProof]):
        TauList = []
        for initProof in initProofs.values():
            TauList += await initProof.nonRevocInitProof.asTauList()
            TauList += await initProof.primaryInitProof.asTauList()
        return TauList

    def _get_hash(self, CList, TauList, nonce):
        return get_hash_as_int(nonce, *reduce(lambda x, y: x + y, [TauList, CList]))
