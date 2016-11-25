import pytest

from anoncreds.protocol.types import ProofInput, PredicateGE, Claims, ProofClaims
from anoncreds.test.conftest import verifyProof, presentProofAndVerify


def testNoClaims(prover1, verifier, nonce, claimDefGvtId, attrRepo):
    proof = prover1._prepareProof(
        {claimDefGvtId.claimDefKey: ProofClaims(Claims())},
        nonce)
    assert verifyProof(verifier, proof, nonce, prover1, attrRepo, ProofInput([]))


def testNonRevocClaimOnlyEmpty(prover1, verifier, attrRepo,
                               nonce, claimDefGvtId,
                               nonRevocClaimGvtProver1):
    proof = prover1._prepareProof(
        {claimDefGvtId.claimDefKey: ProofClaims(Claims(nonRevocClaim=nonRevocClaimGvtProver1))},
        nonce)
    assert verifyProof(verifier, proof, nonce, prover1, attrRepo, ProofInput([]))


def testPrimaryClaimOnlyEmpty(prover1, verifier, primaryClaimGvtProver1, nonce, claimDefGvtId,
                              attrRepo):
    proof = prover1._prepareProof(
        {claimDefGvtId.claimDefKey: ProofClaims(Claims(primaryClaim=primaryClaimGvtProver1))},
        nonce)
    assert verifyProof(verifier, proof, nonce, prover1, attrRepo, ProofInput([]))


def testPrimaryClaimNoPredicates(prover1, verifier, primaryClaimGvtProver1, nonce, claimDefGvtId,
                                 attrRepo):
    revealledAttrs = ['name']
    proofCliams = ProofClaims(Claims(primaryClaim=primaryClaimGvtProver1),
                              revealedAttrs=revealledAttrs)
    proof = prover1._prepareProof({claimDefGvtId.claimDefKey: proofCliams}, nonce)
    assert verifyProof(verifier, proof, nonce, prover1, attrRepo, ProofInput(revealledAttrs))


def testPrimaryClaimPredicatesOnly(prover1, verifier, primaryClaimGvtProver1, nonce, claimDefGvtId,
                                   attrRepo):
    proofCliams = ProofClaims(Claims(primaryClaim=primaryClaimGvtProver1),
                              predicates=[PredicateGE('age', 18)])
    proof = prover1._prepareProof({claimDefGvtId.claimDefKey: proofCliams}, nonce)
    assert verifyProof(verifier, proof, nonce, prover1, attrRepo, ProofInput([]))


def testNoPredicates(prover1, verifier, requestClaimsProver1Gvt, attrRepo):
    proofInput = ProofInput(['name'], [])
    assert presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testMultipleRevealedAttrs(prover1, verifier, requestClaimsProver1Gvt, attrRepo):
    proofInput = ProofInput(['name', 'sex'], [])
    assert presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testGePredicate(prover1, verifier, requestClaimsProver1Gvt, attrRepo):
    proofInput = ProofInput(['name'], [PredicateGE('age', 18)])
    assert presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testGePredicateForEqual(prover1, verifier, requestClaimsProver1Gvt, attrRepo):
    proofInput = ProofInput(['name'], [PredicateGE('age', 28)])
    assert presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testGePredicateNegative(prover1, verifier, requestClaimsProver1Gvt, attrRepo):
    proofInput = ProofInput(['name'], [PredicateGE('age', 29)])
    with pytest.raises(ValueError):
        assert presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testMultipleGePredicate(prover1, verifier, requestClaimsProver1Gvt, attrRepo):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('height', 170)])
    assert presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testMultipleGePredicateNegative(prover1, verifier, requestClaimsProver1Gvt, attrRepo):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('height', 180)])
    with pytest.raises(ValueError):
        presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testNonceShouldBeSame(prover1, verifier, requestClaimsProver1Gvt, attrRepo, nonce, genNonce):
    revealedAttrs = ['name']
    proofInput = ProofInput(revealedAttrs, [])
    proof = prover1.presentProof(proofInput, nonce)
    assert not verifyProof(verifier, proof, genNonce, prover1, attrRepo, ProofInput(revealedAttrs))


def testUParamShouldBeSame(prover1, verifier, attrRepo, fetcherGvt, claimDefGvtId, attrsProver1Gvt):
    prover1._genMasterSecret(claimDefGvtId)
    U = prover1._genU(claimDefGvtId)
    Ur = prover1._genUr(claimDefGvtId)

    U1 = U ** 2
    claims, m2 = fetcherGvt.fetchClaims(prover1.wallet.id, claimDefGvtId, U1, Ur)

    prover1.wallet.submitContextAttr(claimDefGvtId, m2)
    prover1._initPrimaryClaim(claimDefGvtId, claims.primaryClaim)
    prover1._initNonRevocationClaim(claimDefGvtId, claims.nonRevocClaim)

    proofInput = ProofInput(['name'], [])
    assert not presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testUrParamShouldBeSame(prover1, verifier, attrRepo, fetcherGvt, claimDefGvtId, attrsProver1Gvt):
    prover1._genMasterSecret(claimDefGvtId)
    U = prover1._genU(claimDefGvtId)
    Ur = prover1._genUr(claimDefGvtId)

    Ur1 = Ur ** 2
    claims, m2 = fetcherGvt.fetchClaims(prover1.wallet.id, claimDefGvtId, U, Ur1)

    prover1.wallet.submitContextAttr(claimDefGvtId, m2)
    prover1._initPrimaryClaim(claimDefGvtId, claims.primaryClaim)
    with pytest.raises(ValueError):
        prover1._initNonRevocationClaim(claimDefGvtId, claims.nonRevocClaim)
