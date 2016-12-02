import pytest

from anoncreds.protocol.types import ProofInput, PredicateGE, Claims, ProofClaims
from anoncreds.test.conftest import verifyProof, presentProofAndVerify


def testPrimaryClaimOnlyEmpty(prover1, verifier, claimsProver1Gvt, nonce, claimDefGvtId,
                              attrRepo):
    proof = prover1._prepareProof(
        {claimDefGvtId.claimDefKey: ProofClaims(Claims(primaryClaim=claimsProver1Gvt.primaryClaim))},
        nonce)
    assert verifyProof(verifier, proof, nonce, prover1, attrRepo, ProofInput([]))


def testPrimaryClaimNoPredicates(prover1, verifier, claimsProver1Gvt, nonce, claimDefGvtId,
                                 attrRepo):
    revealledAttrs = ['name']
    proofCliams = ProofClaims(Claims(primaryClaim=claimsProver1Gvt.primaryClaim),
                              revealedAttrs=revealledAttrs)
    proof = prover1._prepareProof({claimDefGvtId.claimDefKey: proofCliams}, nonce)
    assert verifyProof(verifier, proof, nonce, prover1, attrRepo, ProofInput(revealledAttrs))


def testPrimaryClaimPredicatesOnly(prover1, verifier, claimsProver1Gvt, nonce, claimDefGvtId,
                                   attrRepo):
    proofCliams = ProofClaims(Claims(primaryClaim=claimsProver1Gvt.primaryClaim),
                              predicates=[PredicateGE('age', 18)])
    proof = prover1._prepareProof({claimDefGvtId.claimDefKey: proofCliams}, nonce)
    assert verifyProof(verifier, proof, nonce, prover1, attrRepo, ProofInput([]))


def testEmpty(prover1, verifier, claimsProver1Gvt, attrRepo):
    assert presentProofAndVerify(verifier, ProofInput(), prover1, attrRepo)


def testNoPredicates(prover1, verifier, claimsProver1Gvt, attrRepo):
    proofInput = ProofInput(['name'], [])
    assert presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testMultipleRevealedAttrs(prover1, verifier, claimsProver1Gvt, attrRepo):
    proofInput = ProofInput(['name', 'sex'], [])
    assert presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testGePredicate(prover1, verifier, claimsProver1Gvt, attrRepo):
    proofInput = ProofInput(['name'], [PredicateGE('age', 18)])
    assert presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testGePredicateForEqual(prover1, verifier, claimsProver1Gvt, attrRepo):
    proofInput = ProofInput(['name'], [PredicateGE('age', 28)])
    assert presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testGePredicateNegative(prover1, verifier, claimsProver1Gvt, attrRepo):
    proofInput = ProofInput(['name'], [PredicateGE('age', 29)])
    with pytest.raises(ValueError):
        assert presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testMultipleGePredicate(prover1, verifier, claimsProver1Gvt, attrRepo):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('height', 170)])
    assert presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testMultipleGePredicateNegative(prover1, verifier, claimsProver1Gvt, attrRepo):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('height', 180)])
    with pytest.raises(ValueError):
        presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testNonceShouldBeSame(prover1, verifier, claimsProver1Gvt, attrRepo, nonce, genNonce):
    revealedAttrs = ['name']
    proofInput = ProofInput(revealedAttrs, [])
    proof = prover1.presentProof(proofInput, nonce)
    assert not verifyProof(verifier, proof, genNonce, prover1, attrRepo, ProofInput(revealedAttrs))


def testUParamShouldBeSame(prover1, verifier, issuerGvt, claimDefGvtId, attrRepo, attrsProver1Gvt, keysGvt,
                           issueAccumulatorGvt):
    claimsReq = prover1.createClaimRequest(claimDefGvtId)

    claimsReq = claimsReq._replace(U=claimsReq.U ** 2)
    claims = issuerGvt.issueClaim(claimDefGvtId, claimsReq)
    prover1.processClaim(claimDefGvtId, claims)

    proofInput = ProofInput(['name'], [])
    assert not presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testUrParamShouldBeSame(prover1, issuerGvt, claimDefGvtId, attrsProver1Gvt, keysGvt, issueAccumulatorGvt):
    claimsReq = prover1.createClaimRequest(claimDefGvtId)

    claimsReq = claimsReq._replace(Ur=claimsReq.Ur ** 2)
    claims = issuerGvt.issueClaim(claimDefGvtId, claimsReq)

    with pytest.raises(ValueError):
        prover1.processClaim(claimDefGvtId, claims)
