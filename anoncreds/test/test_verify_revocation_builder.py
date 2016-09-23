import pytest


def testVerifySingleNonRevoked(witnessCredentialsAndAccum, g, proofRevBuilder, proofRevVerifier):
    witCred, acc = witnessCredentialsAndAccum
    nonRevocProof = proofRevBuilder.prepareProofNonVerification(witCred, acc, g, proofRevVerifier._nonce)
    assert proofRevVerifier.verifyNonRevocation(nonRevocProof, acc)


def testVerifyMultipleNonRevoked(witnessCredentialsAndAccumMultiple, g, proofRevBuilder, proofRevVerifier):
    witCred, acc = witnessCredentialsAndAccumMultiple
    nonRevocProof = proofRevBuilder.prepareProofNonVerification(witCred, acc, g, proofRevVerifier._nonce)
    assert proofRevVerifier.verifyNonRevocation(nonRevocProof, acc)


def testVerifySingleRevoked(witnessCredentialsAndAccum, g, issuanceRevBuilder, proofRevBuilder, proofRevVerifier):
    witCred, acc = witnessCredentialsAndAccum
    issuanceRevBuilder.revoke(acc, g, 1)
    with pytest.raises(ValueError):
        nonRevocProof = proofRevBuilder.prepareProofNonVerification(witCred, acc, g, proofRevVerifier._nonce)
        proofRevVerifier.verifyNonRevocation(nonRevocProof, acc)
