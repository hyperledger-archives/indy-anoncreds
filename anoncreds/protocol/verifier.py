from functools import reduce

from anoncreds.protocol.globals import LARGE_NONCE
from anoncreds.protocol.primary.primary_proof_verifier import PrimaryProofVerifier
from anoncreds.protocol.revocation.accumulators.non_revocation_proof_verifier import NonRevocationProofVerifier
from anoncreds.protocol.types import FullProof
from anoncreds.protocol.utils import get_hash
from anoncreds.protocol.wallet.wallet import Wallet
from config.config import cmod


class Verifier:
    def __init__(self, wallet: Wallet):
        self._wallet = wallet
        self._primaryVerifier = PrimaryProofVerifier(wallet)
        self._nonRevocVerifier = NonRevocationProofVerifier(wallet)

    def generateNonce(self):
        return cmod.integer(cmod.randomBits(LARGE_NONCE))

    def verify(self, proof: FullProof, allRevealedAttrs, nonce):
        TauList = []
        for claimDefKey, proofItem in proof.proofs.items():
            if proofItem.nonRevocProof:
                TauList += self._nonRevocVerifier.verifyNonRevocation(claimDefKey, proof.cHash, proofItem.nonRevocProof)
            if proofItem.primaryProof:
                TauList += self._primaryVerifier.verify(claimDefKey, proof.cHash, proofItem.primaryProof,
                                                        allRevealedAttrs)

        CHver = self._get_hash(proof.CList, TauList, nonce)

        return CHver == proof.cHash

    def _get_hash(self, CList, TauList, nonce):
        return get_hash(nonce, *reduce(lambda x, y: x + y, [TauList, CList]))
