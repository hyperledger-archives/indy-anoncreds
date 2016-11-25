import pytest

from anoncreds.protocol.types import ProofInput, PredicateGE
from anoncreds.test.conftest import presentProofAndVerify


def testNoPredicates(prover1, prover2, verifier, requestAllClaimsProver1, requestAllClaimsProver2, attrRepo):
    proofInput = ProofInput(['name', 'status'], [])
    assert presentProofAndVerify(verifier, proofInput, prover1, attrRepo)
    assert presentProofAndVerify(verifier, proofInput, prover2, attrRepo)


def testGePredicate(prover1, prover2, verifier, requestAllClaimsProver1, requestAllClaimsProver2, attrRepo):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('period', 3)])
    assert presentProofAndVerify(verifier, proofInput, prover1, attrRepo)
    assert presentProofAndVerify(verifier, proofInput, prover2, attrRepo)


def testGePredicateNegativeForOne(prover1, prover2, verifier, requestAllClaimsProver1, requestAllClaimsProver2,
                                  attrRepo):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('period', 9)])
    assert presentProofAndVerify(verifier, proofInput, prover2, attrRepo)
    with pytest.raises(ValueError):
        presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testGePredicateNegativeForBoth(prover1, prover2, verifier, requestAllClaimsProver1, requestAllClaimsProver2,
                                   attrRepo):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('period', 30)])
    with pytest.raises(ValueError):
        presentProofAndVerify(verifier, proofInput, prover1, attrRepo)
    with pytest.raises(ValueError):
        presentProofAndVerify(verifier, proofInput, prover2, attrRepo)
