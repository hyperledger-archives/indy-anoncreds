import pytest

from anoncreds.protocol.types import ProofInput, PredicateGE, Claims
from anoncreds.test.conftest import issuerId1


def testNoPredicates(prover1, allClaimsProver1, verifier, nonce, attrsProver1Gvt):
    proofInput = ProofInput(['name'], [])
    revealedAttrs = {'name': attrsProver1Gvt['name']}

    proof = prover1.findClaimsAndPrepareProof(allClaimsProver1, proofInput, nonce)
    assert verifier.verify(proof, revealedAttrs, nonce)


def testMultipleRevealedAttrs(prover1, allClaimsProver1, verifier, nonce, attrsProver1Gvt):
    proofInput = ProofInput(['name', 'sex'], [])
    revealedAttrs = {'name': attrsProver1Gvt['name'],
                     'sex': attrsProver1Gvt['sex']}

    proof = prover1.findClaimsAndPrepareProof(allClaimsProver1, proofInput, nonce)
    assert verifier.verify(proof, revealedAttrs, nonce)


def testGePredicate(prover1, allClaimsProver1, verifier, nonce, attrsProver1Gvt):
    proofInput = ProofInput(['name'], [PredicateGE('age', 18)])
    revealedAttrs = {'name': attrsProver1Gvt['name']}

    proof = prover1.findClaimsAndPrepareProof(allClaimsProver1, proofInput, nonce)
    assert verifier.verify(proof, revealedAttrs, nonce)


def testGePredicateForEqual(prover1, allClaimsProver1, verifier, nonce, attrsProver1Gvt):
    proofInput = ProofInput(['name'], [PredicateGE('age', 28)])
    revealedAttrs = {'name': attrsProver1Gvt['name']}

    proof = prover1.findClaimsAndPrepareProof(allClaimsProver1, proofInput, nonce)
    assert verifier.verify(proof, revealedAttrs, nonce)


def testGePredicateNegative(prover1, allClaimsProver1, nonce):
    proofInput = ProofInput(['name'], [PredicateGE('age', 29)])
    with pytest.raises(ValueError):
        prover1.findClaimsAndPrepareProof(allClaimsProver1, proofInput, nonce)


def testMultipleGePredicate(prover1, allClaimsProver1, verifier, nonce, attrsProver1Gvt):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('height', 170)])
    revealedAttrs = {'name': attrsProver1Gvt['name']}

    proof = prover1.findClaimsAndPrepareProof(allClaimsProver1, proofInput, nonce)
    assert verifier.verify(proof, revealedAttrs, nonce)


def testMultipleGePredicateNegative(prover1, allClaimsProver1, nonce):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('height', 180)])
    with pytest.raises(ValueError):
        prover1.findClaimsAndPrepareProof(allClaimsProver1, proofInput, nonce)


def testNonceShouldBeSame(prover1, allClaimsProver1, verifier, nonce, genNonce, attrsProver1Gvt):
    proofInput = ProofInput(['name'], [])
    revealedAttrs = {'name': attrsProver1Gvt['name']}

    proof = prover1.findClaimsAndPrepareProof(allClaimsProver1, proofInput, nonce)
    assert not verifier.verify(proof, revealedAttrs, genNonce)


def testUParamShouldBeSame(issuerGvt, prover1, verifier,
                           attrsProver1Gvt, m2GvtProver1,
                           prover1Initializer, nonRevocClaimProver1Gvt, nonce):
    c1 = issuerGvt.issuePrimaryClaim(attrsProver1Gvt, m2GvtProver1, U=1)
    c1 = prover1Initializer.initPrimaryClaim(issuerId1, c1)

    allClaims = {issuerId1: Claims(c1, nonRevocClaimProver1Gvt)}
    proofInput = ProofInput(['name'], [])
    revealedAttrs = {'name': attrsProver1Gvt['name']}

    proof = prover1.findClaimsAndPrepareProof(allClaims, proofInput, nonce)
    assert not verifier.verify(proof, revealedAttrs, nonce)


def testUrParamShouldBeSame(issuerGvt, m2GvtProver1, prover1Initializer):
    c2 = issuerGvt.issueNonRevocationClaim(m2GvtProver1, Ur=1)
    with pytest.raises(ValueError):
        prover1Initializer.initNonRevocationClaim(issuerId1, c2)
