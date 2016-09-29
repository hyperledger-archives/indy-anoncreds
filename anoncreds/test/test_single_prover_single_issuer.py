import pytest

from anoncreds.protocol.types import ProofInput, PredicateGE, Claims, ProofClaims
from anoncreds.test.conftest import issuerId1


def testNoClaims(prover1, verifier, nonce):
    proof = prover1.prepareProof(
        {issuerId1: ProofClaims(Claims())},
        nonce)
    assert verifier.verify(proof, [], nonce)


def testNonRevocClaimOnly(prover1, verifier, initNonRevocClaimProver1Gvt, nonce):
    proof = prover1.prepareProof(
        {issuerId1: ProofClaims(Claims(nonRevocClaim=initNonRevocClaimProver1Gvt))},
        nonce)
    assert verifier.verify(proof, [], nonce)


def testPrimaryClaimOnlyEmpty(prover1, verifier, initPrimaryClaimProver1Gvt, nonce):
    proof = prover1.prepareProof(
        {issuerId1: ProofClaims(Claims(primaryClaim=initPrimaryClaimProver1Gvt))},
        nonce)
    assert verifier.verify(proof, [], nonce)


def testPrimaryClaimNoPredicates(prover1, verifier, initPrimaryClaimProver1Gvt, attrsProver1Gvt, nonce):
    revealedAttrs = {'name': attrsProver1Gvt['name']}
    proofCliams = ProofClaims(Claims(primaryClaim=initPrimaryClaimProver1Gvt),
                              revealedAttrs=['name'])
    proof = prover1.prepareProof({issuerId1: proofCliams}, nonce)
    assert verifier.verify(proof, revealedAttrs, nonce)


def testPrimaryClaimPredicatesOnly(prover1, verifier, initPrimaryClaimProver1Gvt, nonce):
    proofCliams = ProofClaims(Claims(primaryClaim=initPrimaryClaimProver1Gvt),
                              predicates=[PredicateGE('age', 18)])
    proof = prover1.prepareProof({issuerId1: proofCliams}, nonce)
    assert verifier.verify(proof, [], nonce)


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
                           prover1Initializer, nonRevocClaimProver1Gvt,
                           prover1UGvt, nonce):
    incorrectU = prover1UGvt[0] ** 2
    c1 = issuerGvt.issuePrimaryClaim(attrsProver1Gvt, m2GvtProver1, U=incorrectU)
    c1 = prover1Initializer.initPrimaryClaim(issuerId1, c1)

    allClaims = {issuerId1: Claims(c1, nonRevocClaimProver1Gvt)}
    proofInput = ProofInput(['name'], [])
    revealedAttrs = {'name': attrsProver1Gvt['name']}

    proof = prover1.findClaimsAndPrepareProof(allClaims, proofInput, nonce)
    assert not verifier.verify(proof, revealedAttrs, nonce)


def testUrParamShouldBeSame(issuerGvt, m2GvtProver1, prover1Initializer, prover1UGvt):
    incorrectUr = prover1UGvt[1] ** 2
    c2 = issuerGvt.issueNonRevocationClaim(m2GvtProver1, Ur=incorrectUr)
    with pytest.raises(ValueError):
        prover1Initializer.initNonRevocationClaim(issuerId1, c2)
