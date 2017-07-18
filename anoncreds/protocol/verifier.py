from functools import reduce

from anoncreds.protocol.globals import LARGE_NONCE
from anoncreds.protocol.primary.primary_proof_verifier import \
    PrimaryProofVerifier
from anoncreds.protocol.revocation.accumulators.non_revocation_proof_verifier import \
    NonRevocationProofVerifier
from anoncreds.protocol.types import FullProof, ProofRequest
from anoncreds.protocol.utils import get_hash_as_int, isCryptoInteger
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

    async def verify(self, proofRequest: ProofRequest, proof: FullProof):
        """
        Verifies a proof from the prover.

        :param proofRequest: description of a proof to be presented (revealed
        attributes, predicates, timestamps for non-revocation)
        :param proof: a proof
        :return: True if verified successfully and false otherwise.
        """

        if proofRequest.verifiableAttributes.keys() != proof.requestedProof.revealed_attrs.keys():
            raise ValueError('Received attributes ={} do not correspond to requested={}'.format(
                proof.requestedProof.revealed_attrs.keys(), proofRequest.verifiableAttributes.keys()))

        if proofRequest.predicates.keys() != proof.requestedProof.predicates.keys():
            raise ValueError('Received predicates ={} do not correspond to requested={}'.format(
                proof.requestedProof.predicates.keys(), proofRequest.predicates.keys()))

        TauList = []
        for (uuid, proofItem) in proof.proofs.items():
            if proofItem.proof.nonRevocProof:
                TauList += await self._nonRevocVerifier.verifyNonRevocation(
                    proofRequest, proofItem.schema_seq_no, proof.aggregatedProof.cHash,
                    proofItem.proof.nonRevocProof)
            if proofItem.proof.primaryProof:
                TauList += await self._primaryVerifier.verify(proofItem.schema_seq_no,
                                                              proof.aggregatedProof.cHash,
                                                              proofItem.proof.primaryProof)

        CHver = self._get_hash(proof.aggregatedProof.CList, self._prepare_collection(TauList),
                               cmod.integer(proofRequest.nonce))

        return CHver == proof.aggregatedProof.cHash

    def _prepare_collection(self, values):
        return [cmod.toInt(el) if isCryptoInteger(el) else el for el in values]

    def _get_hash(self, CList, TauList, nonce):
        return get_hash_as_int(nonce,
                               *reduce(lambda x, y: x + y, [TauList, CList]))
