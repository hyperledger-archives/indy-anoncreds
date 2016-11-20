from functools import reduce
from typing import Dict

from anoncreds.protocol.globals import LARGE_NONCE
from anoncreds.protocol.primary.primary_proof_verifier import PrimaryProofVerifier
from anoncreds.protocol.revocation.accumulators.non_revocation_proof_verifier import NonRevocationProofVerifier
from anoncreds.protocol.types import PublicData, FullProof, CredentialDefinition
from anoncreds.protocol.utils import get_hash
from config.config import cmod


class Verifier:
    def __init__(self, id, publicData: Dict[CredentialDefinition, PublicData]):
        self.id = id

        publicDataPrimary = {credDef : pub.pubPrimary for credDef, pub in publicData.items()}
        publicDataRevoc = {credDef: pub.pubRevoc for credDef, pub in publicData.items() if pub.pubRevoc}

        self._primaryVerifier = PrimaryProofVerifier(publicDataPrimary)
        if publicDataRevoc:
            self._nonRevocVerifier = NonRevocationProofVerifier(publicDataRevoc)

    @classmethod
    def generateNonce(self):
        return cmod.integer(cmod.randomBits(LARGE_NONCE))

    def verify(self, proof: FullProof, allRevealedAttrs, nonce):
        TauList = []
        for credDef, proofItem in proof.proofs.items():
            if proofItem.nonRevocProof:
                TauList += self._nonRevocVerifier.verifyNonRevocation(credDef, proof.cHash, proofItem.nonRevocProof)
            if proofItem.primaryProof:
                TauList += self._primaryVerifier.verify(credDef, proof.cHash, proofItem.primaryProof, allRevealedAttrs)

        CHver = self._get_hash(proof.CList, TauList, nonce)

        return CHver == proof.cHash

    def _get_hash(self, CList, TauList, nonce):
        return get_hash(nonce, *reduce(lambda x, y: x + y, [TauList, CList]))

    def __repr__(self):
        return str(self.__dict__)
