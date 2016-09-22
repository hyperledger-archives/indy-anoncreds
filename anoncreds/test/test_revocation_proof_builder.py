from anoncreds.protocol.revocation.accumulators.accumulator_definition import AccumulatorDefinition
from anoncreds.protocol.revocation.accumulators.issuance_revocation_builder import IssuanceRevocationBuilder
from anoncreds.protocol.revocation.accumulators.proof_revocation_builder import ProofRevocationBuilder

L = 5
issuerId = "issuer1"
proverId = "prover1"
accId = "acc1"

def testUpdateWitness(prover):
    accDef = AccumulatorDefinition()
    revPk, revSk = accDef.genRevocationKeys()
    acc, g, accSk = accDef.issueAccumulator(accId, revPk, L)

    issuanceRevBuilder = IssuanceRevocationBuilder(accDef.group, revPk, revSk)
    proofRevBuilder = ProofRevocationBuilder(issuerId, accDef.group, revPk, prover._ms)

    witCred = issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    # in sync initially
    assert witCred.witi.V == acc.V

    # not changed as in sync
    oldOmega = witCred.witi.omega
    proofRevBuilder._updateWitness(witCred, acc, g)
    assert witCred.witi.V == acc.V
    assert oldOmega == witCred.witi.omega

    # not in sync
    acc.V.add(2)
    assert witCred.witi.V != acc.V

    # witness is updated
    oldOmega = witCred.witi.omega
    proofRevBuilder._updateWitness(witCred, acc, g)
    assert witCred.witi.V == acc.V
    assert oldOmega != witCred.witi.omega


def testPresentationWitnessCred(prover):
    accDef = AccumulatorDefinition()
    revPk, revSk = accDef.genRevocationKeys()
    acc, g, accSk = accDef.issueAccumulator(accId, revPk, L)

    issuanceRevBuilder = IssuanceRevocationBuilder(accDef.group, revPk, revSk)
    proofRevBuilder = ProofRevocationBuilder(issuerId, accDef.group, revPk, prover._ms)

    witCred = issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    oldV = witCred.v
    witCred = proofRevBuilder._getPresentationWitnessCredential( witCred)
    assert oldV + proofRevBuilder._vrPrime == witCred.v


def testWitnessCredentials(prover):
    accDef = AccumulatorDefinition()
    revPk, revSk = accDef.genRevocationKeys()
    acc, g, accSk = accDef.issueAccumulator(accId, revPk, L)

    issuanceRevBuilder = IssuanceRevocationBuilder(accDef.group, revPk, revSk)
    proofRevBuilder = ProofRevocationBuilder(issuerId, accDef.group, revPk, prover._ms)

    witCred = issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    witCred = proofRevBuilder._getPresentationWitnessCredential(witCred)
    assert proofRevBuilder._testWitnessCredential( witCred, acc)


def testWitnessCredentialsMultipleIssued(prover):
    accDef = AccumulatorDefinition()
    revPk, revSk = accDef.genRevocationKeys()
    acc, g, accSk = accDef.issueAccumulator(accId, revPk, L)

    issuanceRevBuilder = IssuanceRevocationBuilder(accDef.group, revPk, revSk)
    proofRevBuilder = ProofRevocationBuilder(issuerId, accDef.group, revPk, prover._ms)

    issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    witCred = issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    witCred = proofRevBuilder._getPresentationWitnessCredential(witCred)
    assert proofRevBuilder._testWitnessCredential( witCred, acc)


def testCAndTauList(prover):
    accDef = AccumulatorDefinition()
    revPk, revSk = accDef.genRevocationKeys()
    acc, g, accSk = accDef.issueAccumulator(accId, revPk, L)

    issuanceRevBuilder = IssuanceRevocationBuilder(accDef.group, revPk, revSk)
    proofRevBuilder = ProofRevocationBuilder(issuerId, accDef.group, revPk, prover._ms)

    witCred = issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    witCred = proofRevBuilder._getPresentationWitnessCredential(witCred)
    witCred = proofRevBuilder._updateWitness(witCred, acc, g)
    assert proofRevBuilder.testProof(witCred, acc)


def testCAndTauListMultipleIssued(prover):
    accDef = AccumulatorDefinition()
    revPk, revSk = accDef.genRevocationKeys()
    acc, g, accSk = accDef.issueAccumulator(accId, revPk, L)

    issuanceRevBuilder = IssuanceRevocationBuilder(accDef.group, revPk, revSk)
    proofRevBuilder = ProofRevocationBuilder(issuerId, accDef.group, revPk, prover._ms)

    issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    witCred = issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)

    witCred = proofRevBuilder._getPresentationWitnessCredential(witCred)
    witCred = proofRevBuilder._updateWitness(witCred, acc, g)
    assert proofRevBuilder.testProof(witCred, acc)


def testPrepareNonRevocProof(prover):
    accDef = AccumulatorDefinition()
    revPk, revSk = accDef.genRevocationKeys()
    acc, g, accSk = accDef.issueAccumulator(accId, revPk, L)

    issuanceRevBuilder = IssuanceRevocationBuilder(accDef.group, revPk, revSk)
    proofRevBuilder = ProofRevocationBuilder(issuerId, accDef.group, revPk, prover._ms)

    witCred = issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    witCred = proofRevBuilder._getPresentationWitnessCredential(witCred)
    assert proofRevBuilder.testProof(witCred, acc)