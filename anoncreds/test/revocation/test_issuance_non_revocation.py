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
