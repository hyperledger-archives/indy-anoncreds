from functools import reduce
from typing import Dict

from charm.core.math.integer import randomBits, integer

from anoncreds.protocol.globals import LARGE_MASTER_SECRET, LARGE_M2_TILDE
from anoncreds.protocol.primary.primary_proof_builder import PrimaryClaimInitializer, PrimaryProofBuilder
from anoncreds.protocol.revocation.accumulators.non_revocation_proof_builder import NonRevocationClaimInitializer, \
    NonRevocationProofBuilder
from anoncreds.protocol.types import PrimaryClaim, NonRevocationClaim, PublicData, \
    Proof, Claims, InitProof, ProofInput, ProofClaims, FullProof, T, CredentialDefinition
from anoncreds.protocol.utils import get_hash


class ProverInitializer:
    def __init__(self, id, m2: Dict[CredentialDefinition, T], publicData: Dict[CredentialDefinition, PublicData], ms):
        self.id = id

        self._primaryClaimInitializer = PrimaryClaimInitializer(publicData, ms)
        self._nonRevocClaimInitializer = NonRevocationClaimInitializer(publicData, ms, m2)

    @classmethod
    def genMasterSecret(cls):
        return integer(randomBits(LARGE_MASTER_SECRET))

    def getU(self, credDef):
        return self._primaryClaimInitializer.getU(credDef)

    def getUr(self, credDef):
        return self._nonRevocClaimInitializer.getUr(credDef)

    def initPrimaryClaim(self, credDef, claim: PrimaryClaim):
        return self._primaryClaimInitializer.preparePrimaryClaim(credDef, claim)

    def initNonRevocationClaim(self, credDef, claim: NonRevocationClaim):
        return self._nonRevocClaimInitializer.initNonRevocationClaim(credDef, claim)

    def __repr__(self):
        return str(self.__dict__)


class Prover:
    def __init__(self, id, publicData: Dict[str, PublicData], m1):
        self.id = id

        self._m1 = m1

        self._primaryProofBuilder = PrimaryProofBuilder(publicData, self._m1)
        self._nonRevocProofBuilder = NonRevocationProofBuilder(publicData)

    def updateNonRevocationClaims(self, proofClaims: Dict[CredentialDefinition, ProofClaims]) -> Dict[
        str, NonRevocationClaim]:
        c2s = {}
        for credDef, proofClaim in proofClaims.items():
            c2s[credDef] = self._nonRevocProofBuilder.updateNonRevocationClaim(credDef,
                                                                               proofClaim.claims.nonRevocClaim)
        return c2s

    def updateNonRevocationClaim(self, credDef, c2: NonRevocationClaim):
        return self._nonRevocProofBuilder.updateNonRevocationClaim(credDef, c2)

    @classmethod
    def findClaims(cls, allClaims: Dict[CredentialDefinition, Claims], proofInput: ProofInput) -> Dict[
        CredentialDefinition, ProofClaims]:
        revealedAttrs, predicates = set(proofInput.revealedAttrs), set(proofInput.predicates)

        proofClaims = {}
        foundRevealedAttrs = set()
        foundPredicates = set()
        for credDef, claim in allClaims.items():
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
                proofClaims[credDef] = ProofClaims(claim, revealedAttrsForClaim, predicatesForClaim)

        if foundRevealedAttrs != revealedAttrs:
            raise ValueError("A claim isn't found for the following attributes: {}", revealedAttrs - foundRevealedAttrs)
        if foundPredicates != predicates:
            raise ValueError("A claim isn't found for the following predicates: {}", predicates - foundPredicates)

        return proofClaims

    def findClaimsAndPrepareProof(self, allClaims: Dict[CredentialDefinition, Claims], proofInput: ProofInput,
                                  nonce) -> FullProof:
        proofClaims = Prover.findClaims(allClaims, proofInput)
        return self.prepareProof(proofClaims, nonce)

    def prepareProof(self, claims: Dict[CredentialDefinition, ProofClaims], nonce) -> FullProof:
        m1Tilde = integer(randomBits(LARGE_M2_TILDE))
        initProofs = {}
        CList = []
        TauList = []

        # 1. init proofs
        for credDef, val in claims.items():
            c1, c2, revealedAttrs, predicates = val.claims.primaryClaim, val.claims.nonRevocClaim, val.revealedAttrs, val.predicates

            nonRevocInitProof = None
            if c2:
                nonRevocInitProof = self._nonRevocProofBuilder.initProof(credDef, c2)
                CList += nonRevocInitProof.asCList()
                TauList += nonRevocInitProof.asTauList()

            primaryInitProof = None
            if c1:
                m2Tilde = integer(int(nonRevocInitProof.TauListParams.m2)) if nonRevocInitProof else None
                primaryInitProof = self._primaryProofBuilder.initProof(credDef, c1, revealedAttrs, predicates,
                                                                       m1Tilde, m2Tilde)
                CList += primaryInitProof.asCList()
                TauList += primaryInitProof.asTauList()

            initProof = InitProof(nonRevocInitProof, primaryInitProof)
            initProofs[credDef] = initProof

        # 2. hash
        cH = self._get_hash(CList, TauList, nonce)

        # 3. finalize proofs
        proofs = {}
        for credDef, initProof in initProofs.items():
            nonRevocProof = self._nonRevocProofBuilder.finalizeProof(credDef, cH, initProof.nonRevocInitProof)
            primaryProof = self._primaryProofBuilder.finalizeProof(credDef, cH, initProof.primaryInitProof)
            proofs[credDef] = Proof(nonRevocProof, primaryProof)

        return FullProof(cH, proofs, CList)

    def _getCList(self, initProofs: Dict[CredentialDefinition, InitProof]):
        CList = []
        for initProof in initProofs.values():
            CList += initProof.nonRevocInitProof.asCList()
            CList += initProof.primaryInitProof.asCList()
            return CList

    def _getTauList(self, initProofs: Dict[CredentialDefinition, InitProof]):
        TauList = []
        for initProof in initProofs.values():
            TauList += initProof.nonRevocInitProof.asTauList()
            TauList += initProof.primaryInitProof.asTauList()
        return TauList

    def _get_hash(self, CList, TauList, nonce):
        return get_hash(nonce, *reduce(lambda x, y: x + y, [TauList, CList]))
