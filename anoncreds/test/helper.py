from anoncreds.protocol.prover import Prover


def verify(proofInput, allRevealedAttrs, allClaims, prover, verifier, nonce):
    proofClaims = Prover.findClaims(allClaims, proofInput)
    proof = prover.prepareProof(proofClaims, nonce)
    assert verifier.verify(proof, allRevealedAttrs, nonce)
