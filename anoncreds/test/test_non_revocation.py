import pytest

from anoncreds.protocol.types import ProofClaims, Claims, ProofInput
from anoncreds.protocol.utils import groupIdentityG1
from anoncreds.test.conftest import presentProofAndVerify


def testIssueRevocationCredential(nonRevocClaimGvtProver1, issuerGvt, claimDefGvtId):
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


def testRevoce(nonRevocClaimGvtProver1, issuerGvt, claimDefGvtId):
    acc = issuerGvt.wallet.getAccumulator(claimDefGvtId)
    accPk = issuerGvt.wallet.getPublicKeyAccumulator(claimDefGvtId)

    issuerGvt.revoke(claimDefGvtId, 1)

    newAcc = issuerGvt.wallet.getAccumulator(claimDefGvtId)
    assert not newAcc.V
    assert newAcc.acc == groupIdentityG1()


def testUpdateWitnessNotChangedIfInSync(nonRevocClaimGvtProver1, claimDefGvtId, prover1):
    acc = prover1.wallet.getAccumulator(claimDefGvtId)

    # not changed as in sync
    oldOmega = nonRevocClaimGvtProver1.witness.omega

    c2 = prover1._nonRevocProofBuilder.updateNonRevocationClaim(claimDefGvtId.claimDefKey, nonRevocClaimGvtProver1)
    assert c2.witness.V == acc.V
    assert oldOmega == c2.witness.omega


def testUpdateWitnessChangedIfOutOfSync(nonRevocClaimGvtProver1, issuerGvt, claimDefGvtId, prover1):
    acc = issuerGvt.wallet.getAccumulator(claimDefGvtId)

    # not in sync
    acc.V.add(3)
    assert nonRevocClaimGvtProver1.witness.V != acc.V

    # witness is updated
    oldOmega = nonRevocClaimGvtProver1.witness.omega
    c2 = prover1._nonRevocProofBuilder.updateNonRevocationClaim(claimDefGvtId.claimDefKey, nonRevocClaimGvtProver1)
    assert c2.witness.V == acc.V
    assert oldOmega != c2.witness.omega


def testUpdateRevocedWitness(nonRevocClaimGvtProver1, issuerGvt, claimDefGvtId, prover1):
    issuerGvt.revoke(claimDefGvtId, 1)
    with pytest.raises(ValueError):
        prover1._nonRevocProofBuilder.updateNonRevocationClaim(claimDefGvtId.claimDefKey, nonRevocClaimGvtProver1)


def testInitNonRevocClaim(claimDefGvtId, prover1, attrsProver1Gvt, fetcherGvt):
    prover1._genMasterSecret(claimDefGvtId)
    U = prover1._genU(claimDefGvtId)
    Ur = prover1._genUr(claimDefGvtId)

    claims, m2 = fetcherGvt.fetchClaims(prover1.wallet.id, claimDefGvtId, U, Ur)
    prover1.wallet.submitContextAttr(claimDefGvtId, m2)
    oldV = claims.nonRevocClaim.v
    prover1._initPrimaryClaim(claimDefGvtId, claims.primaryClaim)
    prover1._initNonRevocationClaim(claimDefGvtId, claims.nonRevocClaim)

    newC2 = prover1.wallet.getClaims(claimDefGvtId).nonRevocClaim
    vrPrime = prover1.wallet.getNonRevocClaimInitData(claimDefGvtId).vPrime
    assert oldV + vrPrime == newC2.v


def testCAndTauList(nonRevocClaimGvtProver1, claimDefGvtId, prover1):
    proofRevBuilder = prover1._nonRevocProofBuilder
    assert proofRevBuilder.testProof(claimDefGvtId.claimDefKey, nonRevocClaimGvtProver1)


def testRevocedWithUpdateWitness(claimDefGvtId, issuerGvt, prover1, verifier, attrRepo, requestClaimsProver1Gvt):
    issuerGvt.revoke(claimDefGvtId, 1)

    proofInput = ProofInput(['name'], [])
    with pytest.raises(ValueError):
        presentProofAndVerify(verifier, proofInput, prover1, attrRepo)

def testRevocedWithoutUpdateWitness(claimDefGvtId, issuerGvt, prover1, verifier, attrRepo, requestClaimsProver1Gvt):
    proofInput = ProofInput(['name'], [])
    nonce = verifier.generateNonce()
    proof = prover1.presentProof(proofInput, nonce)

    issuerGvt.revoke(claimDefGvtId, 1)

    revealedAttrs = attrRepo.getRevealedAttributesForProver(prover1, proofInput.revealedAttrs).encoded()
    return verifier.verify(proofInput, proof, revealedAttrs, nonce)
