from anoncreds.protocol.revocation.accumulators.issuance_revocation_builder import IssuanceRevocationBuilder


def testIssueRevocationCredential(accumulatorWithAllKeys, genUr):
    revPk, revSk, acc, g, accSk = accumulatorWithAllKeys

    issuanceRevBuilder = IssuanceRevocationBuilder(revPk, revSk)
    witCred = issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, genUr)

    assert witCred
    assert witCred.witi
    assert witCred.witi.V
    assert witCred.i == 1
    assert witCred.witi.gi == g[1]

    assert acc.V
    assert acc.acc != 1


def testRevoce(accumulatorWithAllKeys, genUr):
    revPk, revSk, acc, g, accSk = accumulatorWithAllKeys

    issuanceRevBuilder = IssuanceRevocationBuilder(revPk, revSk)
    issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, genUr)

    issuanceRevBuilder.revoke(acc, g, 1)

    assert not acc.V
    assert acc.acc == acc.pk.z / acc.pk.z
