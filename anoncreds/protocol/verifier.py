from functools import reduce

from anoncreds.protocol.globals import LARGE_NONCE
from anoncreds.protocol.primary.primary_proof_verifier import \
    PrimaryProofVerifier
from anoncreds.protocol.revocation.accumulators.non_revocation_proof_verifier import \
    NonRevocationProofVerifier
from anoncreds.protocol.types import FullProof, ProofInput
from anoncreds.protocol.utils import get_hash_as_int
from anoncreds.protocol.wallet.wallet import Wallet
from config.config import cmod


class Verifier:
    def __init__(self, wallet: Wallet):
        self.wallet = wallet
        self._primaryVerifier = PrimaryProofVerifier(wallet)
        self._nonRevocVerifier = NonRevocationProofVerifier(wallet)

    @property
    def verifierId(self):
        return self.wallet.walletId

    def generateNonce(self):
        return cmod.integer(cmod.randomBits(LARGE_NONCE))

    async def verify(self, proofInput: ProofInput, proof: FullProof,
                     allRevealedAttrs, nonce):
        """
        Verifies a proof from the prover.

        :param proofInput: description of a proof to be presented (revealed
        attributes, predicates, timestamps for non-revocation)
        :param proof: a proof
        :param allRevealedAttrs: values of revealed attributes
        :param nonce: verifier's nonce
        :return: True if verified successfully and false otherwise.
        """
        TauList = []
        for schemaKey, proofItem in zip(proof.schemaKeys, proof.proofs):
            if proofItem.nonRevocProof:
                TauList += await self._nonRevocVerifier.verifyNonRevocation(
                    proofInput, schemaKey, proof.cHash,
                    proofItem.nonRevocProof)
            if proofItem.primaryProof:
                TauList += await self._primaryVerifier.verify(proofInput,
                                                              schemaKey,
                                                              proof.cHash,
                                                              proofItem.primaryProof,
                                                              allRevealedAttrs)

        CHver = self._get_hash(proof.CList, TauList, nonce)

        return CHver == proof.cHash

    def _get_hash(self, CList, TauList, nonce):
        return get_hash_as_int(nonce,
                               *reduce(lambda x, y: x + y, [TauList, CList]))
