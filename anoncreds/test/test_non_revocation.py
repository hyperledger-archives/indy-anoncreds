import pytest

from anoncreds.protocol.types import ProofClaims, Claims


def testIssueRevocationCredential(nonRevocClaimProver1Gvt, issueAccumulatorGvt):
    acc, g = issueAccumulatorGvt[0], issueAccumulatorGvt[1]
    assert nonRevocClaimProver1Gvt
    assert nonRevocClaimProver1Gvt.witness
    assert nonRevocClaimProver1Gvt.witness.V
    assert nonRevocClaimProver1Gvt.i == 1
    assert nonRevocClaimProver1Gvt.witness.gi == g[1]

    assert acc.V
    assert acc.acc != 1

    assert nonRevocClaimProver1Gvt.witness.V == acc.V


def testRevoce(issuerGvt, issueAccumulatorGvt):
    acc, g, accPk = issueAccumulatorGvt[0], issueAccumulatorGvt[1], issueAccumulatorGvt[2]

    issuerGvt.revoke(1)

    assert not acc.V
    assert acc.acc == accPk.z / accPk.z


def testUpdateWitnessNotChangedIfInSync(newIssueAccumulatorGvt, newProver1, newNonRevocClaimProver1Gvt, credDefGvt):
    acc = newIssueAccumulatorGvt[0]

    # not changed as in sync
    oldOmega = newNonRevocClaimProver1Gvt.witness.omega

    c2 = newProver1.updateNonRevocationClaim(credDefGvt, newNonRevocClaimProver1Gvt)
    assert c2.witness.V == acc.V
    assert oldOmega == c2.witness.omega


def testUpdateWitnessChangedIfOutOfSync(newIssueAccumulatorGvt, newProver1, newNonRevocClaimProver1Gvt, credDefGvt):
    acc = newIssueAccumulatorGvt[0]

    # not in sync
    acc.V.add(3)
    assert newNonRevocClaimProver1Gvt.witness.V != acc.V

    # witness is updated
    oldOmega = newNonRevocClaimProver1Gvt.witness.omega
    c2 = newProver1.updateNonRevocationClaim(credDefGvt, newNonRevocClaimProver1Gvt)
    assert c2.witness.V == acc.V
    assert oldOmega != c2.witness.omega


def testUpdateRevocedWitness(newProver1, newIssuerGvt, newInitNonRevocClaimProver1Gvt, credDefGvt):
    newIssuerGvt.revoke(1)
    with pytest.raises(ValueError):
        newProver1.updateNonRevocationClaim(credDefGvt, newInitNonRevocClaimProver1Gvt)


def testInitNonRevocClaim(newProver1Initializer, newNonRevocClaimProver1Gvt, credDefGvt):
    oldV = newNonRevocClaimProver1Gvt.v
    c2 = newProver1Initializer.initNonRevocationClaim(credDefGvt, newNonRevocClaimProver1Gvt)
    assert oldV + newProver1Initializer._nonRevocClaimInitializer._vrPrime[credDefGvt] == c2.v


def testCAndTauList(newProver1, newInitNonRevocClaimProver1Gvt, credDefGvt):
    proofRevBuilder = newProver1._nonRevocProofBuilder
    assert proofRevBuilder.testProof(credDefGvt, newInitNonRevocClaimProver1Gvt)


def testRevocedWithoutUpdateWitness(newProver1, newIssuerGvt, verifier, nonce,
                                    newInitNonRevocClaimProver1Gvt, credDefGvt):
    newIssuerGvt.revoke(1)

    proof = newProver1.prepareProof(
        {credDefGvt: ProofClaims(Claims(nonRevocClaim=newInitNonRevocClaimProver1Gvt))},
        nonce)
    assert not verifier.verify(proof, [], nonce)
