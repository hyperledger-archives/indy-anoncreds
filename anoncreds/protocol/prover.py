from functools import reduce
from typing import Dict, Sequence, Any

from anoncreds.protocol.globals import LARGE_MASTER_SECRET, LARGE_M2_TILDE
from anoncreds.protocol.primary.primary_proof_builder import PrimaryClaimInitializer, PrimaryProofBuilder
from anoncreds.protocol.revocation.accumulators.non_revocation_proof_builder import NonRevocationClaimInitializer, \
    NonRevocationProofBuilder
from anoncreds.protocol.types import PrimaryClaim, NonRevocationClaim, Proof, InitProof, ProofInput, ProofClaims, \
    FullProof, \
    ClaimDefinition, ID, ClaimDefinitionKey, ClaimRequest, Claims
from anoncreds.protocol.utils import get_hash
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

    def createClaimRequest(self, id: ID, proverId=None, reqNonRevoc=True) -> ClaimRequest:
        self._genMasterSecret(id)
        U = self._genU(id)
        Ur = None if not reqNonRevoc else self._genUr(id)
        proverId = proverId if proverId else self.id
        return ClaimRequest(userId=proverId, U=U, Ur=Ur)

    def createClaimRequests(self, ids: Sequence[ID], proverId=None, reqNonRevoc=True) -> Dict[ID, ClaimRequest]:
        return {id: self.createClaimRequest(id, proverId, reqNonRevoc) for id in ids}

    def processClaim(self, id: ID, claims: Claims):
        self.wallet.submitContextAttr(id, claims.primaryClaim.m2)
        self._initPrimaryClaim(id, claims.primaryClaim)
        if claims.nonRevocClaim:
            self._initNonRevocationClaim(id, claims.nonRevocClaim)

    def processClaims(self, allClaims: Dict[ID, Claims]):
        return [self.processClaim(id, claims) for id, claims in allClaims.items()]

    def presentProof(self, proofInput: ProofInput, nonce) -> (FullProof, Dict[str, Any]):
        claims, revealedAttrsWithValues = self._findClaims(proofInput)
        return (self._prepareProof(claims, nonce), revealedAttrsWithValues)

    #
    # REQUEST CLAIMS
    #

    def _genMasterSecret(self, id: ID):
        ms = cmod.integer(cmod.randomBits(LARGE_MASTER_SECRET))
        self.wallet.submitMasterSecret(id=id, ms=ms)

    def _genU(self, id: ID):
        claimInitData = self._primaryClaimInitializer.genClaimInitData(id)
        self.wallet.submitPrimaryClaimInitData(id=id, claimInitData=claimInitData)
        return claimInitData.U

    def _genUr(self, id: ID):
        claimInitData = self._nonRevocClaimInitializer.genClaimInitData(id)
        self.wallet.submitNonRevocClaimInitData(id=id, claimInitData=claimInitData)
        return claimInitData.U

    def _initPrimaryClaim(self, id: ID, claim: PrimaryClaim):
        claim = self._primaryClaimInitializer.preparePrimaryClaim(id, claim)
        self.wallet.submitPrimaryClaim(id=id, claim=claim)

    def _initNonRevocationClaim(self, id: ID, claim: NonRevocationClaim):
        claim = self._nonRevocClaimInitializer.initNonRevocationClaim(id, claim)
        self.wallet.submitNonRevocClaim(id=id, claim=claim)

    #
    # PRESENT PROOF
    #

    def _findClaims(self, proofInput: ProofInput) -> (Dict[ClaimDefinitionKey, ProofClaims], Dict[str, Any]):
        revealedAttrs, predicates = set(proofInput.revealedAttrs), set(proofInput.predicates)

        proofClaims = {}
        foundRevealedAttrs = set()
        foundPredicates = set()
        revealedAttrsWithValues = {}

        for credDefKey, claim in self.wallet.getAllClaims().items():
            revealedAttrsForClaim = []
            predicatesForClaim = []

            for revealedAttr in revealedAttrs:
                if revealedAttr in claim.primaryClaim.attrs:
                    revealedAttrsForClaim.append(revealedAttr)
                    foundRevealedAttrs.add(revealedAttr)
                    revealedAttrsWithValues[revealedAttr] = claim.primaryClaim.attrs[revealedAttr]

            for predicate in predicates:
                if predicate.attrName in claim.primaryClaim.attrs:
                    predicatesForClaim.append(predicate)
                    foundPredicates.add(predicate)

            if revealedAttrsForClaim or predicatesForClaim:
                proofClaims[credDefKey] = ProofClaims(claim, revealedAttrsForClaim, predicatesForClaim)

        if foundRevealedAttrs != revealedAttrs:
            raise ValueError("A claim isn't found for the following attributes: {}", revealedAttrs - foundRevealedAttrs)
        if foundPredicates != predicates:
            raise ValueError("A claim isn't found for the following predicates: {}", predicates - foundPredicates)

        return (proofClaims, revealedAttrsWithValues)

    def _prepareProof(self, claims: Dict[ClaimDefinitionKey, ProofClaims], nonce) -> FullProof:
        m1Tilde = cmod.integer(cmod.randomBits(LARGE_M2_TILDE))
        initProofs = {}
        CList = []
        TauList = []

        # 1. init proofs
        for claimDefKey, val in claims.items():
            c1, c2, revealedAttrs, predicates = val.claims.primaryClaim, val.claims.nonRevocClaim, val.revealedAttrs, val.predicates

            nonRevocInitProof = None
            if c2:
                nonRevocInitProof = self._nonRevocProofBuilder.initProof(claimDefKey, c2)
                CList += nonRevocInitProof.asCList()
                TauList += nonRevocInitProof.asTauList()

            primaryInitProof = None
            if c1:
                m2Tilde = cmod.integer(int(nonRevocInitProof.TauListParams.m2)) if nonRevocInitProof else None
                primaryInitProof = self._primaryProofBuilder.initProof(claimDefKey, c1, revealedAttrs, predicates,
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
                nonRevocProof = self._nonRevocProofBuilder.finalizeProof(claimDefKey, cH, initProof.nonRevocInitProof)
            primaryProof = self._primaryProofBuilder.finalizeProof(claimDefKey, cH, initProof.primaryInitProof)
            proofs.append(Proof(primaryProof, nonRevocProof))

        return FullProof(cH, claimDefKeys, proofs, CList)

    def _getCList(self, initProofs: Dict[ClaimDefinition, InitProof]):
        CList = []
        for initProof in initProofs.values():
            CList += initProof.nonRevocInitProof.asCList()
            CList += initProof.primaryInitProof.asCList()
            return CList

    def _getTauList(self, initProofs: Dict[ClaimDefinition, InitProof]):
        TauList = []
        for initProof in initProofs.values():
            TauList += initProof.nonRevocInitProof.asTauList()
            TauList += initProof.primaryInitProof.asTauList()
        return TauList

    def _get_hash(self, CList, TauList, nonce):
        return get_hash(nonce, *reduce(lambda x, y: x + y, [TauList, CList]))
