from functools import reduce
from typing import Dict

from charm.core.math.integer import randomBits, integer

from anoncreds.protocol.globals import LARGE_MASTER_SECRET, LARGE_M2_TILDE
from anoncreds.protocol.primary.primary_proof_builder import PrimaryClaimInitializer, PrimaryProofBuilder
from anoncreds.protocol.revocation.accumulators.non_revocation_proof_builder import NonRevocationClaimInitializer, \
    NonRevocationProofBuilder
from anoncreds.protocol.types import PrimaryClaim, NonRevocationClaim, PublicData, \
    Proof, Claims, InitProof, ProofInput, ProofClaims, FullProof, T
from anoncreds.protocol.utils import get_hash


class ProverInitializer:
    def __init__(self, id, m2: Dict[str, T], publicData: Dict[str, PublicData], ms):
        self.id = id

        self._primaryClaimInitializer = PrimaryClaimInitializer(publicData, ms)
        self._nonRevocClaimInitializer = NonRevocationClaimInitializer(publicData, ms, m2)

    @classmethod
    def genMasterSecret(cls):
        return integer(randomBits(LARGE_MASTER_SECRET))

    def getU(self, issuerId):
        return self._primaryClaimInitializer.getU(issuerId)

    def getUr(self, issuerId):
        return self._nonRevocClaimInitializer.getUr(issuerId)

    def initPrimaryClaim(self, issuerId, claim: PrimaryClaim):
        return self._primaryClaimInitializer.preparePrimaryClaim(issuerId, claim)

    def initNonRevocationClaim(self, issuerId, claim: NonRevocationClaim):
        return self._nonRevocClaimInitializer.initNonRevocationClaim(issuerId, claim)

    def __repr__(self):
        return str(self.__dict__)


class Prover:
    def __init__(self, id, publicData: Dict[str, PublicData], m1):
        self.id = id

        self._m1 = m1

        self._primaryProofBuilder = PrimaryProofBuilder(publicData, self._m1)
        self._nonRevocProofBuilder = NonRevocationProofBuilder(publicData)

    # TODO: use a special type instead of str for IssuerId
    def updateNonRevocationClaims(self, proofClaims: Dict[str, ProofClaims]) -> Dict[str, NonRevocationClaim]:
        c2s = {}
        for issuerId, proofClaim in proofClaims.items():
            c2s[issuerId] = self._nonRevocProofBuilder.updateNonRevocationClaim(issuerId,
                                                                                proofClaim.claims.nonRevocClaim)
        return c2s

    def updateNonRevocationClaim(self, issuerId, c2: NonRevocationClaim):
        return self._nonRevocProofBuilder.updateNonRevocationClaim(issuerId, c2)

    @classmethod
    def findClaims(cls, allClaims: Dict[str, Claims], proofInput: ProofInput) -> Dict[str, ProofClaims]:
        revealedAttrs, predicates = set(proofInput.revealedAttrs), set(proofInput.predicates)

        proofClaims = {}
        foundRevealedAttrs = set()
        foundPredicates = set()
        for issuerId, claim in allClaims.items():
            revealedAttrsForClaim = []
            predicatesForClaim = []

            for revealedAttr in revealedAttrs:
                if revealedAttr in claim.primaryClaim.attrs:
                    revealedAttrsForClaim.append(revealedAttr)
                    foundRevealedAttrs.add(revealedAttr)

            for predicate in predicates:
                if predicate.attrName in claim.primaryClaim.attrs:
                    predicatesForClaim.append(predicate)
                    foundPredicates.add(predicate)

            if revealedAttrsForClaim or predicatesForClaim:
                proofClaims[issuerId] = ProofClaims(claim, revealedAttrsForClaim, predicatesForClaim)

        if foundRevealedAttrs != revealedAttrs:
            raise ValueError("A claim isn't found for the following attributes: {}", revealedAttrs - foundRevealedAttrs)
        if foundPredicates != predicates:
            raise ValueError("A claim isn't found for the following predicates: {}", predicates - foundPredicates)

        return proofClaims

    def findClaimsAndPrepareProof(self, allClaims: Dict[str, Claims], proofInput: ProofInput, nonce) -> FullProof:
        proofClaims = Prover.findClaims(allClaims, proofInput)
        return self.prepareProof(proofClaims, nonce)

    def prepareProof(self, claims: Dict[str, ProofClaims], nonce) -> FullProof:
        m1Tilde = integer(randomBits(LARGE_M2_TILDE))
        initProofs = {}
        CList = []
        TauList = []

        # 1. init proofs
        for issuerId, val in claims.items():
            c1, c2, revealedAttrs, predicates = val.claims.primaryClaim, val.claims.nonRevocClaim, val.revealedAttrs, val.predicates

            nonRevocInitProof = None
            if c2:
                nonRevocInitProof = self._nonRevocProofBuilder.initProof(issuerId, c2)
                CList += nonRevocInitProof.asCList()
                TauList += nonRevocInitProof.asTauList()

            primaryInitProof = None
            if c1:
                m2Tilde = integer(int(nonRevocInitProof.TauListParams.m2)) if nonRevocInitProof else None
                primaryInitProof = self._primaryProofBuilder.initProof(issuerId, c1, revealedAttrs, predicates,
                                                                       m1Tilde, m2Tilde)
                CList += primaryInitProof.asCList()
                TauList += primaryInitProof.asTauList()

            initProof = InitProof(nonRevocInitProof, primaryInitProof)
            initProofs[issuerId] = initProof

        # 2. hash
        cH = self._get_hash(CList, TauList, nonce)

        # 3. finalize proofs
        proofs = {}
        for issuerId, initProof in initProofs.items():
            nonRevocProof = self._nonRevocProofBuilder.finalizeProof(issuerId, cH, initProof.nonRevocInitProof)
            primaryProof = self._primaryProofBuilder.finalizeProof(issuerId, cH, initProof.primaryInitProof)
            proofs[issuerId] = Proof(nonRevocProof, primaryProof)

        return FullProof(cH, proofs, CList)

    def _getCList(self, initProofs: Dict[str, InitProof]):
        CList = []
        for initProof in initProofs.values():
            CList += initProof.nonRevocInitProof.asCList()
            CList += initProof.primaryInitProof.asCList()
            return CList

    def _getTauList(self, initProofs: Dict[str, InitProof]):
        TauList = []
        for initProof in initProofs.values():
            TauList += initProof.nonRevocInitProof.asTauList()
            TauList += initProof.primaryInitProof.asTauList()
        return TauList

    def _get_hash(self, CList, TauList, nonce):
        return get_hash(nonce, *reduce(lambda x, y: x + y, [TauList, CList]))
