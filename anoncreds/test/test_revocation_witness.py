from anoncreds.protocol.revocation.accumulators.accumulator_definition import AccumulatorDefinition
from anoncreds.protocol.revocation.accumulators.proof_revocation_builder import ProofRevocationBuilder
from anoncreds.protocol.revocation.accumulators.issuance_revocation_builder import IssuanceRevocationBuilder

def testWitnessCredentialsOneCred(prover):
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

    i = 1;
    witCred = issuanceRevBuilder.issueRevocationCredential(proverId, acc, accSk,
                                                 g, proofRevBuilder.Ur[issuerId], i)

    assert proofRevBuilder.testWitnessCredential(issuerId, witCred, acc)


def testWitnessCredentialsTwoCred(prover):
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

    assert proofRevBuilder.testWitnessCredential(issuerId, witCred, acc)

