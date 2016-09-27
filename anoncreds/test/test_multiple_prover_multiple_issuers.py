import pytest

from anoncreds.protocol.types import ProofInput, PredicateGE


# def testNoPredicates(prover1, allClaimsProver1, allClaimsProver2,
#                      verifier, nonce,
#                      attrsProver1Gvt, attrsProver1Xyz,
#                      attrsProver2Gvt, attrsProver2Xyz):
#     proofInput = ProofInput(['name', 'status'], [])
#     revealedAttrs1 = {'name': attrsProver1Gvt['name'],
#                       'status': attrsProver1Xyz['status']}
#     revealedAttrs2 = {'name': attrsProver2Gvt['name'],
#                       'status': attrsProver2Xyz['status']}
#
#     proof1 = prover1.findClaimsAndPrepareProof(allClaimsProver1, proofInput, nonce)
#     #proof2 = prover2.findClaimsAndPrepareProof(allClaimsProver2, proofInput, nonce)
#     assert verifier.verify(proof1, revealedAttrs1, nonce)
#     #assert verifier.verify(proof2, revealedAttrs2, nonce)
#
#
# def testGePredicate(prover1, prover2, allClaimsProver1, allClaimsProver2,
#                     verifier, nonce,
#                     attrsProver1Gvt, attrsProver2Gvt):
#     proofInput = ProofInput(['name'], [PredicateGE('period', 5)])
#     revealedAttrs1 = {'name': attrsProver1Gvt['name']}
#     revealedAttrs2 = {'name': attrsProver2Gvt['name']}
#
#     proof1 = prover1.findClaimsAndPrepareProof(allClaimsProver1, proofInput, nonce)
#     proof2 = prover2.findClaimsAndPrepareProof(allClaimsProver2, proofInput, nonce)
#     assert verifier.verify(proof1, revealedAttrs1, nonce)
#     assert verifier.verify(proof2, revealedAttrs2, nonce)


def testGePredicateNegative(prover1, prover2, allClaimsProver1, allClaimsProver2,
                            verifier, nonce,
                            attrsProver2Gvt):
    proofInput = ProofInput(['name'], [PredicateGE('period', 9)])
    revealedAttrs2 = {'name': attrsProver2Gvt['name']}

    proof2 = prover2.findClaimsAndPrepareProof(allClaimsProver2, proofInput, nonce)
    assert verifier.verify(proof2, revealedAttrs2, nonce)

    with pytest.raises(ValueError):
        prover1.findClaimsAndPrepareProof(allClaimsProver1, proofInput, nonce)


def testMultipleGePredicate(prover1, prover2, allClaimsProver1, allClaimsProver2, nonce):
    proofInput = ProofInput(['name'], [PredicateGE('period', 30)])
    with pytest.raises(ValueError):
        prover2.findClaimsAndPrepareProof(allClaimsProver2, proofInput, nonce)
    with pytest.raises(ValueError):
        prover1.findClaimsAndPrepareProof(allClaimsProver1, proofInput, nonce)
