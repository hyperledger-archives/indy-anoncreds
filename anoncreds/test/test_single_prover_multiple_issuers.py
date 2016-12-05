import pytest

from anoncreds.protocol.types import ProofInput, PredicateGE
from anoncreds.test.conftest import presentProofAndVerify


def testNoPredicates(prover1, verifier, claimsProver1):
    proofInput = ProofInput(['name', 'status'], [])
    assert presentProofAndVerify(verifier, proofInput, prover1)


def testGePredicate(prover1, verifier, claimsProver1):
    proofInput = ProofInput(['name'], [PredicateGE('period', 5)])
    assert presentProofAndVerify(verifier, proofInput, prover1)


def testGePredicateForEqual(prover1, verifier, claimsProver1):
    proofInput = ProofInput(['name'], [PredicateGE('period', 8)])
    assert presentProofAndVerify(verifier, proofInput, prover1)


def testGePredicateNegative(prover1, verifier, claimsProver1):
    proofInput = ProofInput(['name'], [PredicateGE('period', 9)])
    with pytest.raises(ValueError):
        presentProofAndVerify(verifier, proofInput, prover1)


def testMultipleGePredicate(prover1, verifier, claimsProver1):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('period', 5)])
    presentProofAndVerify(verifier, proofInput, prover1)


def testMultipleGePredicateMultipleRevealed(prover1, verifier, claimsProver1):
    proofInput = ProofInput(['name', 'status'],
                            [PredicateGE('age', 18),
                             PredicateGE('period', 5)])
    presentProofAndVerify(verifier, proofInput, prover1)


def testMultipleGePredicateNegative(prover1, verifier, claimsProver1):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('period', 9)])
    with pytest.raises(ValueError):
        presentProofAndVerify(verifier, proofInput, prover1)
