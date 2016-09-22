from anoncreds.protocol.revocation.accumulators.accumulator_definition import AccumulatorDefinition
from anoncreds.protocol.revocation.accumulators.issuance_revocation_builder import IssuanceRevocationBuilder
from anoncreds.protocol.revocation.accumulators.proof_revocation_builder import ProofRevocationBuilder
from anoncreds.protocol.revocation.accumulators.proof_revocation_verifier import ProofRevocationVerifier


def testSingleNonRevoked(prover, verifier):
    L = 5
    issuerId = "issuer1"
    proverId = "prover1"

    accDef = AccumulatorDefinition()
    revPk, revSk = accDef.genRevocationKeys(L)
    acc, g, accSk = accDef.issueAccumulator(revPk)

    revPks = {issuerId: revPk}
    accums = {issuerId: acc}
    groups = {issuerId: accDef.group}
    issuanceRevBuilder = IssuanceRevocationBuilder(accDef.group, revPk, revSk)
    proofRevBuilder = ProofRevocationBuilder(groups, revPks, prover._ms)
    proofRevVerifier = ProofRevocationVerifier(groups, revPks, verifier.nonce)

    witCred = issuanceRevBuilder.issueRevocationCredential(proverId, acc, accSk,
                                                           g, proofRevBuilder.Ur[issuerId], 1)
    witCred = proofRevBuilder.getPresentationWitnessCredential(issuerId, witCred)

    nonRevocProof = proofRevBuilder.prepareProofNonVerification({issuerId: witCred}, accums, verifier.nonce)

    assert proofRevVerifier.verifyNonRevocation(issuerId, nonRevocProof, acc)


def testSingleRevoked(prover, verifier):
    L = 5
    issuerId = "issuer1"
    proverId = "prover1"

    accDef = AccumulatorDefinition()
    revPk, revSk = accDef.genRevocationKeys(L)
    acc, g, accSk = accDef.issueAccumulator(revPk)

    revPks = {issuerId: revPk}
    accums = {issuerId: acc}
    groups = {issuerId: accDef.group}
    issuanceRevBuilder = IssuanceRevocationBuilder(accDef.group, revPk, revSk)
    proofRevBuilder = ProofRevocationBuilder(groups, revPks, prover._ms)
    proofRevVerifier = ProofRevocationVerifier(groups, revPks, verifier.nonce)

    i = 1
    witCred = issuanceRevBuilder.issueRevocationCredential(proverId, acc, accSk,
                                                           g, proofRevBuilder.Ur[issuerId], i)
    issuanceRevBuilder.revoke(acc, g, i)
    witCred = proofRevBuilder.getPresentationWitnessCredential(issuerId, witCred)

    nonRevocProof = proofRevBuilder.prepareProofNonVerification({issuerId: witCred}, accums, verifier.nonce)

    assert not proofRevVerifier.verifyNonRevocation(issuerId, nonRevocProof, acc)
