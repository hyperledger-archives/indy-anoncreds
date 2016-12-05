import pytest

from anoncreds.protocol.types import ProofInput, PredicateGE, Claims, ProofClaims
from anoncreds.test.conftest import presentProofAndVerify


def testPrimaryClaimOnlyEmpty(prover1, verifier, claimsProver1Gvt, nonce):
    proofInput = ProofInput([])
    claims, revealedAttrs = prover1._findClaims(proofInput)
    claims = {claimDefKey: ProofClaims(Claims(primaryClaim=proofClaim.claims.primaryClaim))
              for claimDefKey, proofClaim in claims.items()}
    proof = prover1._prepareProof(claims, nonce)
    assert verifier.verify(proofInput, proof, revealedAttrs, nonce)


def testPrimaryClaimNoPredicates(prover1, verifier, claimsProver1Gvt, nonce, claimDefGvtId,
                                 attrRepo):
    revealledAttrs = ['name']
    proofInput = ProofInput(revealledAttrs)
    claims, revealedAttrs = prover1._findClaims(proofInput)
    claims = {
        claimDefKey: ProofClaims(Claims(primaryClaim=proofClaim.claims.primaryClaim), revealedAttrs=revealledAttrs)
        for claimDefKey, proofClaim in claims.items()}
    proof = prover1._prepareProof(claims, nonce)
    assert verifier.verify(proofInput, proof, revealedAttrs, nonce)


def testPrimaryClaimPredicatesOnly(prover1, verifier, claimsProver1Gvt, nonce, claimDefGvtId,
                                   attrRepo):
    predicates = [PredicateGE('age', 18)]
    proofInput = ProofInput(predicates=predicates)
    claims, revealedAttrs = prover1._findClaims(proofInput)
    claims = {claimDefKey: ProofClaims(Claims(primaryClaim=proofClaim.claims.primaryClaim), predicates=predicates)
              for claimDefKey, proofClaim in claims.items()}
    proof = prover1._prepareProof(claims, nonce)
    assert verifier.verify(proofInput, proof, revealedAttrs, nonce)


def testEmpty(prover1, verifier, claimsProver1Gvt):
    assert presentProofAndVerify(verifier, ProofInput(), prover1)


def testNoPredicates(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(['name'], [])
    assert presentProofAndVerify(verifier, proofInput, prover1)


def testMultipleRevealedAttrs(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(['name', 'sex'], [])
    assert presentProofAndVerify(verifier, proofInput, prover1)


def testGePredicate(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(['name'], [PredicateGE('age', 18)])
    assert presentProofAndVerify(verifier, proofInput, prover1)


def testGePredicateForEqual(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(['name'], [PredicateGE('age', 28)])
    assert presentProofAndVerify(verifier, proofInput, prover1)


def testGePredicateNegative(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(['name'], [PredicateGE('age', 29)])
    with pytest.raises(ValueError):
        assert presentProofAndVerify(verifier, proofInput, prover1)


def testMultipleGePredicate(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('height', 170)])
    assert presentProofAndVerify(verifier, proofInput, prover1)


def testMultipleGePredicateNegative(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('height', 180)])
    with pytest.raises(ValueError):
        presentProofAndVerify(verifier, proofInput, prover1)


def testNonceShouldBeSame(prover1, verifier, claimsProver1Gvt, nonce, genNonce):
    revealedAttrs = ['name']
    proofInput = ProofInput(revealedAttrs, [])
    proof, revealedAttrs = prover1.presentProof(proofInput, nonce)
    assert not verifier.verify(proofInput, proof, revealedAttrs, genNonce)


def testUParamShouldBeSame(prover1, verifier, issuerGvt, claimDefGvtId, attrsProver1Gvt, keysGvt,
                           issueAccumulatorGvt):
    claimsReq = prover1.createClaimRequest(claimDefGvtId)

    claimsReq = claimsReq._replace(U=claimsReq.U ** 2)
    claims = issuerGvt.issueClaim(claimDefGvtId, claimsReq)
    prover1.processClaim(claimDefGvtId, claims)

    proofInput = ProofInput(['name'], [])
    assert not presentProofAndVerify(verifier, proofInput, prover1)


def testUrParamShouldBeSame(prover1, issuerGvt, claimDefGvtId, attrsProver1Gvt, keysGvt, issueAccumulatorGvt):
    claimsReq = prover1.createClaimRequest(claimDefGvtId)

    claimsReq = claimsReq._replace(Ur=claimsReq.Ur ** 2)
    claims = issuerGvt.issueClaim(claimDefGvtId, claimsReq)

    with pytest.raises(ValueError):
        prover1.processClaim(claimDefGvtId, claims)
