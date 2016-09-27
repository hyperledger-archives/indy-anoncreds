# def testUpdateWitnessNotChangedIfInSync(issueAccumulatorGvt, prover1, nonRevocClaimProver1Gvt):
#     acc = issueAccumulatorGvt[0]
#
#     # not changed as in sync
#     oldOmega = nonRevocClaimProver1Gvt.witness.omega
#
#     c2 = prover1.updateNonRevocationClaim(issuerId1, nonRevocClaimProver1Gvt)
#     assert c2.witness.V == acc.V
#     assert oldOmega == c2.witness.omega
#
#
# def testUpdateWitnessChangedIfOutOfSync(issueAccumulatorGvt, prover1, nonRevocClaimProver1Gvt):
#     acc = issueAccumulatorGvt[0]
#
#     # not in sync
#     acc.V.add(2)
#     assert nonRevocClaimProver1Gvt.witness.V != acc.V
#
#     # witness is updated
#     oldOmega = nonRevocClaimProver1Gvt.witness.omega
#     c2 = prover1.updateNonRevocationClaim(issuerId1, nonRevocClaimProver1Gvt)
#     assert c2.witness.V == acc.V
#     assert oldOmega != c2.witness.omega
#
#
# def testInitWitnessCred(prover1Initializer, nonRevocClaimProver1Gvt):
#     oldV = nonRevocClaimProver1Gvt.v
#     c2 = prover1Initializer.initNonRevocationClaim(issuerId1, nonRevocClaimProver1Gvt)
#     assert oldV + prover1Initializer._nonRevocClaimInitializer._vrPrime[issuerId1] == c2.v
#
#
# def testCAndTauList(prover1Initializer, initNonRevocClaimProver1Gvt, issueAccumulatorGvt):
#     acc = issueAccumulatorGvt[0]
#     proofRevBuilder = prover1Initializer._nonRevocClaimInitializer
#     assert proofRevBuilder.testProof(initNonRevocClaimProver1Gvt, acc)
