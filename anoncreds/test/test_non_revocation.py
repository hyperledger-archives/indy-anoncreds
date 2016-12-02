import pytest

from anoncreds.protocol.types import ProofInput
from anoncreds.protocol.utils import groupIdentityG1
from anoncreds.test.conftest import presentProofAndVerify


def testIssueRevocationCredential(claimsProver1Gvt, issuerGvt, claimDefGvtId):
    nonRevocClaimGvtProver1 = claimsProver1Gvt.nonRevocClaim
    acc = issuerGvt.wallet.getAccumulator(claimDefGvtId)
    tails = issuerGvt.wallet.getTails(claimDefGvtId)
    assert nonRevocClaimGvtProver1
    assert nonRevocClaimGvtProver1.witness
    assert nonRevocClaimGvtProver1.witness.V
    assert nonRevocClaimGvtProver1.i == 1
    assert nonRevocClaimGvtProver1.witness.gi == tails[1]

    assert acc.V
    assert acc.acc != 1

    assert nonRevocClaimGvtProver1.witness.V == acc.V


def testRevoce(claimsProver1Gvt, issuerGvt, claimDefGvtId):
    issuerGvt.revoke(claimDefGvtId, 1)
    newAcc = issuerGvt.wallet.getAccumulator(claimDefGvtId)
    assert not newAcc.V
    assert newAcc.acc == groupIdentityG1()


def testUpdateWitnessNotChangedIfInSync(claimsProver1Gvt, claimDefGvtId, prover1):
    nonRevocClaimGvtProver1 = claimsProver1Gvt.nonRevocClaim
    acc = prover1.wallet.getAccumulator(claimDefGvtId)

    # not changed as in sync
    oldOmega = nonRevocClaimGvtProver1.witness.omega

    c2 = prover1._nonRevocProofBuilder.updateNonRevocationClaim(claimDefGvtId.claimDefKey, nonRevocClaimGvtProver1)
    assert c2.witness.V == acc.V
    assert oldOmega == c2.witness.omega


def testUpdateWitnessChangedIfOutOfSync(claimsProver1Gvt, issuerGvt, claimDefGvtId, prover1):
    nonRevocClaimGvtProver1 = claimsProver1Gvt.nonRevocClaim
    acc = issuerGvt.wallet.getAccumulator(claimDefGvtId)

    # not in sync
    acc.V.add(3)
    assert nonRevocClaimGvtProver1.witness.V != acc.V

    # witness is updated
    oldOmega = nonRevocClaimGvtProver1.witness.omega
    c2 = prover1._nonRevocProofBuilder.updateNonRevocationClaim(claimDefGvtId.claimDefKey, nonRevocClaimGvtProver1)
    assert c2.witness.V == acc.V
    assert oldOmega != c2.witness.omega


def testUpdateRevocedWitness(claimsProver1Gvt, issuerGvt, claimDefGvtId, prover1):
    nonRevocClaimGvtProver1 = claimsProver1Gvt.nonRevocClaim
    issuerGvt.revoke(claimDefGvtId, 1)
    with pytest.raises(ValueError):
        prover1._nonRevocProofBuilder.updateNonRevocationClaim(claimDefGvtId.claimDefKey, nonRevocClaimGvtProver1)


def testInitNonRevocClaim(claimDefGvtId, prover1, issuerGvt, attrsProver1Gvt, keysGvt, issueAccumulatorGvt):
    claimsReq = prover1.createClaimRequest(claimDefGvtId)
    claims = issuerGvt.issueClaim(claimDefGvtId, claimsReq)

    oldV = claims.nonRevocClaim.v
    prover1.processClaim(claimDefGvtId, claims)
    newC2 = prover1.wallet.getClaims(claimDefGvtId).nonRevocClaim
    vrPrime = prover1.wallet.getNonRevocClaimInitData(claimDefGvtId).vPrime

    assert oldV + vrPrime == newC2.v


def testCAndTauList(claimsProver1Gvt, claimDefGvtId, prover1):
    nonRevocClaimGvtProver1 = claimsProver1Gvt.nonRevocClaim
    proofRevBuilder = prover1._nonRevocProofBuilder
    assert proofRevBuilder.testProof(claimDefGvtId.claimDefKey, nonRevocClaimGvtProver1)


def testRevocedWithUpdateWitness(claimDefGvtId, issuerGvt, prover1, verifier, attrRepo, claimsProver1Gvt):
    issuerGvt.revoke(claimDefGvtId, 1)

    proofInput = ProofInput(['name'], [])
    with pytest.raises(ValueError):
        presentProofAndVerify(verifier, proofInput, prover1, attrRepo)


def testRevocedWithoutUpdateWitness(claimDefGvtId, issuerGvt, prover1, verifier, attrRepo, claimsProver1Gvt):
    proofInput = ProofInput(['name'], [])
    nonce = verifier.generateNonce()
    proof = prover1.presentProof(proofInput, nonce)

    issuerGvt.revoke(claimDefGvtId, 1)

    revealedAttrs = attrRepo.getRevealedAttributesForProver(prover1, proofInput.revealedAttrs).encoded()
    return verifier.verify(proofInput, proof, revealedAttrs, nonce)
