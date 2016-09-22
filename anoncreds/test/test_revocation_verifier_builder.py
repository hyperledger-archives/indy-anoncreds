import pytest

from anoncreds.protocol.revocation.accumulators.accumulator_definition import AccumulatorDefinition
from anoncreds.protocol.revocation.accumulators.issuance_revocation_builder import IssuanceRevocationBuilder
from anoncreds.protocol.revocation.accumulators.proof_revocation_builder import ProofRevocationBuilder
from anoncreds.protocol.revocation.accumulators.proof_revocation_verifier import ProofRevocationVerifier

L = 5
issuerId = "issuer1"
proverId = "prover1"
accId = "acc1"


def testVerifySingleNonRevoked(prover, verifier):
    accDef = AccumulatorDefinition()
    revPk, revSk = accDef.genRevocationKeys()
    acc, g, accSk = accDef.issueAccumulator(accId, revPk, L)

    issuanceRevBuilder = IssuanceRevocationBuilder(accDef.group, revPk, revSk)
    proofRevBuilder = ProofRevocationBuilder(issuerId, accDef.group, revPk, prover._ms)
    proofRevVerifier = ProofRevocationVerifier(accDef.group, revPk, verifier.nonce)

    witCred = issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    nonRevocProof = proofRevBuilder.prepareProofNonVerification(witCred, acc, g, verifier.nonce)

    assert proofRevVerifier.verifyNonRevocation(nonRevocProof, acc)


def testVerifyMultipleNonRevoked(prover, verifier):
    accDef = AccumulatorDefinition()
    revPk, revSk = accDef.genRevocationKeys()
    acc, g, accSk = accDef.issueAccumulator(accId, revPk, L)

    issuanceRevBuilder = IssuanceRevocationBuilder(accDef.group, revPk, revSk)
    proofRevBuilder = ProofRevocationBuilder(issuerId, accDef.group, revPk, prover._ms)
    proofRevVerifier = ProofRevocationVerifier(accDef.group, revPk, verifier.nonce)

    issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    witCred = issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    nonRevocProof = proofRevBuilder.prepareProofNonVerification(witCred, acc, g, verifier.nonce)

    assert proofRevVerifier.verifyNonRevocation(nonRevocProof, acc)


def testVerifySingleRevoked(prover, verifier):
    accDef = AccumulatorDefinition()
    revPk, revSk = accDef.genRevocationKeys()
    acc, g, accSk = accDef.issueAccumulator(accId, revPk, L)

    issuanceRevBuilder = IssuanceRevocationBuilder(accDef.group, revPk, revSk)
    proofRevBuilder = ProofRevocationBuilder(issuerId, accDef.group, revPk, prover._ms)
    proofRevVerifier = ProofRevocationVerifier(accDef.group, revPk, verifier.nonce)

    witCred = issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    issuanceRevBuilder.revoke(acc, g, 1)

    with pytest.raises(ValueError):
        nonRevocProof = proofRevBuilder.prepareProofNonVerification(witCred, acc, g, verifier.nonce)
        proofRevVerifier.verifyNonRevocation(nonRevocProof, acc)
