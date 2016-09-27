import pytest

from anoncreds.protocol.types import ProofInput, PredicateGE


def testNoPredicates(prover1, allClaimsProver1, verifier, nonce, attrsProver1Gvt, attrsProver1Xyz):
    proofInput = ProofInput(['name', 'status'], [])
    revealedAttrs = {'name': attrsProver1Gvt['name'],
                     'status': attrsProver1Xyz['status']}

    proof = prover1.findClaimsAndPrepareProof(allClaimsProver1, proofInput, nonce)
    assert verifier.verify(proof, revealedAttrs, nonce)


def testGePredicate(prover1, allClaimsProver1, verifier, nonce, attrsProver1Gvt):
    proofInput = ProofInput(['name'], [PredicateGE('period', 5)])
    revealedAttrs = {'name': attrsProver1Gvt['name']}

    proof = prover1.findClaimsAndPrepareProof(allClaimsProver1, proofInput, nonce)
    assert verifier.verify(proof, revealedAttrs, nonce)


def testGePredicateForEqual(prover1, allClaimsProver1, verifier, nonce, attrsProver1Gvt):
    proofInput = ProofInput(['name'], [PredicateGE('period', 8)])
    revealedAttrs = {'name': attrsProver1Gvt['name']}

    proof = prover1.findClaimsAndPrepareProof(allClaimsProver1, proofInput, nonce)
    assert verifier.verify(proof, revealedAttrs, nonce)


def testGePredicateNegative(prover1, allClaimsProver1, nonce):
    proofInput = ProofInput(['name'], [PredicateGE('period', 9)])
    with pytest.raises(ValueError):
        prover1.findClaimsAndPrepareProof(allClaimsProver1, proofInput, nonce)


def testMultipleGePredicate(prover1, allClaimsProver1, verifier, nonce, attrsProver1Gvt):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('period', 5)])
    revealedAttrs = {'name': attrsProver1Gvt['name']}

    proof = prover1.findClaimsAndPrepareProof(allClaimsProver1, proofInput, nonce)
    assert verifier.verify(proof, revealedAttrs, nonce)


def testMultipleGePredicateMultipleRevealed(prover1, allClaimsProver1, verifier, nonce, attrsProver1Gvt,
                                            attrsProver1Xyz):
    proofInput = ProofInput(['name', 'status'],
                            [PredicateGE('age', 18),
                             PredicateGE('period', 5)])
    revealedAttrs = {'name': attrsProver1Gvt['name'],
                     'status': attrsProver1Xyz['status']}

    proof = prover1.findClaimsAndPrepareProof(allClaimsProver1, proofInput, nonce)
    assert verifier.verify(proof, revealedAttrs, nonce)


def testMultipleGePredicateNegative(prover1, allClaimsProver1, verifier, nonce, attrsProver1Gvt):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('period', 9)])
    with pytest.raises(ValueError):
        prover1.findClaimsAndPrepareProof(allClaimsProver1, proofInput, nonce)
