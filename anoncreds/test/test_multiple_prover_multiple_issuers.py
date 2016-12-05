import pytest

from anoncreds.protocol.types import ProofInput, PredicateGE
from anoncreds.test.conftest import presentProofAndVerify


def testNoPredicates(prover1, prover2, verifier, allClaims):
    proofInput = ProofInput(['name', 'status'], [])
    assert presentProofAndVerify(verifier, proofInput, prover1)
    assert presentProofAndVerify(verifier, proofInput, prover2)


def testGePredicate(prover1, prover2, verifier, allClaims):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('period', 3)])
    assert presentProofAndVerify(verifier, proofInput, prover1)
    assert presentProofAndVerify(verifier, proofInput, prover2)


def testGePredicateNegativeForOne(prover1, prover2, verifier, allClaims):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('period', 9)])
    assert presentProofAndVerify(verifier, proofInput, prover2)
    with pytest.raises(ValueError):
        presentProofAndVerify(verifier, proofInput, prover1)


def testGePredicateNegativeForBoth(prover1, prover2, verifier, allClaims):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('period', 30)])
    with pytest.raises(ValueError):
        presentProofAndVerify(verifier, proofInput, prover1)
    with pytest.raises(ValueError):
        presentProofAndVerify(verifier, proofInput, prover2)
