from anoncreds.protocol.revocation.accumulators.accumulator_definition import AccumulatorDefinition
from anoncreds.protocol.revocation.accumulators.proof_revocation_builder import ProofRevocationBuilder
from anoncreds.protocol.revocation.accumulators.issuance_revocation_builder import IssuanceRevocationBuilder

def testUpdateWitness(prover):
    L = 5
    issuerId = "issuer1"
    proverId = "prover1"

    accDef = AccumulatorDefinition()
    revPk, revSk = accDef.genRevocationKeys(L)
    acc, g, accSk = accDef.issueAccumulator(revPk)

    issuanceRevBuilder = IssuanceRevocationBuilder(accDef.group, revPk, revSk)
    proofRevBuilder = ProofRevocationBuilder({issuerId: accDef.group},
                                             {issuerId: revPk},
                                             prover._ms)

    witCred = issuanceRevBuilder.issueRevocationCredential(proverId, acc, accSk,
                                                 g, proofRevBuilder.Ur[issuerId], 1)
    # in sync initially
    assert witCred.witi.V == acc.V

    # not changed as in sync
    oldOmega = witCred.witi.omega
    proofRevBuilder.updateWitness({issuerId: witCred}, {issuerId: acc}, {issuerId: g})
    assert witCred.witi.V == acc.V
    assert oldOmega == witCred.witi.omega

    # not in sync
    acc.V.add(2)
    assert witCred.witi.V != acc.V

    # witness is updated
    oldOmega = witCred.witi.omega
    proofRevBuilder.updateWitness({issuerId: witCred}, {issuerId: acc}, {issuerId: g})
    assert witCred.witi.V == acc.V
    assert oldOmega !=  witCred.witi.omega


def testCAndTauList(prover):
    L = 5
    issuerId = "issuer1"
    proverId = "prover1"

    accDef = AccumulatorDefinition()
    revPk, revSk = accDef.genRevocationKeys(L)
    acc, g, accSk = accDef.issueAccumulator(revPk)

    issuanceRevBuilder = IssuanceRevocationBuilder(accDef.group, revPk, revSk)
    proofRevBuilder = ProofRevocationBuilder({issuerId: accDef.group},
                                             {issuerId: revPk},
                                             prover._ms)

    witCred = issuanceRevBuilder.issueRevocationCredential(proverId, acc, accSk,
                                                 g, proofRevBuilder.Ur[issuerId], 1)

    assert proofRevBuilder.testProof({issuerId: witCred}, {issuerId: acc})


def testCAndTauListTwoCred(prover):
    L = 5
    issuerId = "issuer1"
    proverId = "prover1"

    accDef = AccumulatorDefinition()
    revPk, revSk = accDef.genRevocationKeys(L)
    acc, g, accSk = accDef.issueAccumulator(revPk)

    issuanceRevBuilder = IssuanceRevocationBuilder(accDef.group, revPk, revSk)
    proofRevBuilder = ProofRevocationBuilder({issuerId: accDef.group},
                                             {issuerId: revPk},
                                             prover._ms)

    issuanceRevBuilder.issueRevocationCredential(proverId, acc, accSk,
                                                 g, proofRevBuilder.Ur[issuerId], 1)
    witCred = issuanceRevBuilder.issueRevocationCredential(proverId, acc, accSk,
                                                 g, proofRevBuilder.Ur[issuerId], 2)

    assert proofRevBuilder.testProof({issuerId: witCred}, {issuerId: acc})