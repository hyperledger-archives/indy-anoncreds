import pytest

from anoncreds.protocol.types import ProofInput, PredicateGE
from anoncreds.test.conftest import presentProofAndVerify


def testNoPredicates(prover1, verifier, claimsProver1, attrRepo):
    proofInput = ProofInput(['name', 'status'], [])
    assert presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testGePredicate(prover1, verifier, claimsProver1, attrRepo):
    proofInput = ProofInput(['name'], [PredicateGE('period', 5)])
    assert presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testGePredicateForEqual(prover1, verifier, claimsProver1, attrRepo):
    proofInput = ProofInput(['name'], [PredicateGE('period', 8)])
    assert presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testGePredicateNegative(prover1, verifier, claimsProver1, attrRepo):
    proofInput = ProofInput(['name'], [PredicateGE('period', 9)])
    with pytest.raises(ValueError):
        presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testMultipleGePredicate(prover1, verifier, claimsProver1, attrRepo):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('period', 5)])
    presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testMultipleGePredicateMultipleRevealed(prover1, verifier, claimsProver1, attrRepo):
    proofInput = ProofInput(['name', 'status'],
                            [PredicateGE('age', 18),
                             PredicateGE('period', 5)])
    presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testMultipleGePredicateNegative(prover1, verifier, claimsProver1, attrRepo):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('period', 9)])
    with pytest.raises(ValueError):
        presentProofAndVerify(verifier, proofInput, prover1, attrRepo)
