from anoncreds.protocol.revocation.accumulators.accumulator_definition import AccumulatorDefinition
from anoncreds.protocol.revocation.accumulators.issuance_revocation_builder import IssuanceRevocationBuilder
from anoncreds.protocol.revocation.accumulators.proof_revocation_builder import ProofRevocationBuilder


def testWitnessInSyncInitially(witnessCredentialsAndAccum):
    witCred, acc = witnessCredentialsAndAccum
    assert witCred.witi.V == acc.V


def testUpdateWitnessNotChangedIfInSync(witnessCredentialsAndAccum, g, proofRevBuilder):
    witCred, acc = witnessCredentialsAndAccum
    # not changed as in sync
    oldOmega = witCred.witi.omega
    proofRevBuilder._updateWitness(witCred, acc, g)
    assert witCred.witi.V == acc.V
    assert oldOmega == witCred.witi.omega


def testUpdateWitnessChangedIfOutOfSync(witnessCredentialsAndAccum, g, proofRevBuilder):
    witCred, acc = witnessCredentialsAndAccum

    # not in sync
    acc.V.add(2)
    assert witCred.witi.V != acc.V

    # witness is updated
    oldOmega = witCred.witi.omega
    proofRevBuilder._updateWitness(witCred, acc, g)
    assert witCred.witi.V == acc.V
    assert oldOmega != witCred.witi.omega


def testPresentationWitnessCred(witnessCredentials, proofRevBuilder):
    oldV = witnessCredentials.v
    witCred = proofRevBuilder._getPresentationWitnessCredential(witnessCredentials)
    assert oldV + proofRevBuilder._vrPrime == witCred.v


def testWitnessCredentialsIssuedCorrectly(witnessCredentialsAndAccum, proofRevBuilder):
    witCred, acc = witnessCredentialsAndAccum
    witCred = proofRevBuilder._getPresentationWitnessCredential(witCred)
    assert proofRevBuilder._testWitnessCredential(witCred, acc)


def testWitnessCredentialsMultipleIssued(witnessCredentialsAndAccumMultiple, proofRevBuilder):
    witCred, acc = witnessCredentialsAndAccumMultiple
    witCred = proofRevBuilder._getPresentationWitnessCredential(witCred)
    assert proofRevBuilder._testWitnessCredential(witCred, acc)


def testCAndTauList(witnessCredentialsAndAccum, g, proofRevBuilder):
    witCred, acc = witnessCredentialsAndAccum
    witCred = proofRevBuilder._getPresentationWitnessCredential(witCred)
    witCred = proofRevBuilder._updateWitness(witCred, acc, g)
    assert proofRevBuilder.testProof(witCred, acc)


def testCAndTauListMultipleIssued(witnessCredentialsAndAccumMultiple, g, proofRevBuilder):
    witCred, acc = witnessCredentialsAndAccumMultiple
    witCred = proofRevBuilder._getPresentationWitnessCredential(witCred)
    witCred = proofRevBuilder._updateWitness(witCred, acc, g)
    assert proofRevBuilder.testProof(witCred, acc)


def testPrepareNonRevocProof(witnessCredentialsAndAccum, g, proofRevBuilder, genNonce):
    witCred, acc = witnessCredentialsAndAccum
    assert proofRevBuilder.prepareProofNonVerification(witCred, acc, g, genNonce)


def testPrepareNonRevocProofMultipleIssued(witnessCredentialsAndAccumMultiple, g, proofRevBuilder, genNonce):
    witCred, acc = witnessCredentialsAndAccumMultiple
    assert proofRevBuilder.prepareProofNonVerification(witCred, acc, g, genNonce)

