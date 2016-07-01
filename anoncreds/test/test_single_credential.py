import pytest

from anoncreds.protocol.types import GVT
from anoncreds.test.helper import getPresentationToken


def testSingleProver(credDef1, attrNames1, proverAndAttrs1, verifier1):

    prover, attrs = proverAndAttrs1
    assert len(attrs.encoded()[GVT.name]) == len(attrNames1)

    presentationToken = getPresentationToken({GVT.name: credDef1},
                                             prover,
                                             attrs.encoded())

    nonce = verifier1.generateNonce

    # Prepare proof
    revealedAttrs = ['name']
    proof = prover.prepareProof(credential=presentationToken,
                                 attrs=attrs.encoded(),
                                 revealedAttrs=revealedAttrs,
                                 nonce=nonce)

    # Verify the proof
    verify_status = verifier1.verifyProof(proof=proof,
                                           nonce=nonce,
                                           attrs=attrs.encoded(),
                                           revealedAttrs=revealedAttrs)

    assert verify_status


def testMultipleProvers(credDef1, attrNames1, proverAndAttrs1,
                        proverAndAttrs2, verifier1):

    prover1, attrs1 = proverAndAttrs1
    prover2, attrs2 = proverAndAttrs2
    assert len(attrs1.encoded()[GVT.name]) == len(attrNames1)
    assert len(attrs2.encoded()[GVT.name]) == len(attrNames1)

    presentationToken1 = getPresentationToken({GVT.name: credDef1}, prover1, attrs1.encoded())
    presentationToken2 = getPresentationToken({GVT.name: credDef1}, prover2, attrs2.encoded())

    nonce1 = verifier1.generateNonce
    nonce2 = verifier1.generateNonce

    # Prepare proofs
    revealedAttrs = ['name']
    proof1 = prover1.prepareProof(credential=presentationToken1,
                                   attrs=attrs1.encoded(),
                                   revealedAttrs=revealedAttrs,
                                   nonce=nonce1)
    proof2 = prover2.prepareProof(credential=presentationToken2,
                                   attrs=attrs2.encoded(),
                                   revealedAttrs=revealedAttrs,
                                   nonce=nonce2)

    assert verifier1.verifyProof(proof=proof1, nonce=nonce1,
                                  attrs=attrs1.encoded(),
                                  revealedAttrs=revealedAttrs)
    assert verifier1.verifyProof(proof=proof2, nonce=nonce2,
                                  attrs=attrs2.encoded(),
                                  revealedAttrs=revealedAttrs)


def testNonceShouldBeSame(credDef1, proverAndAttrs1, verifier1, verifierMulti2):
    prover, attrs = proverAndAttrs1

    presentationToken = getPresentationToken({GVT.name: credDef1},
                                             prover,
                                             attrs.encoded())

    nonce1 = verifier1.Nonce
    nonce2 = verifierMulti2.Nonce

    # Prepare proof
    revealedAttrs = ['name']
    proof = prover.prepareProof(credential=presentationToken,
                                attrs=attrs.encoded(),
                                revealedAttrs=revealedAttrs,
                                nonce=nonce1)

    # Verify the proof
    verify_status = verifier1.verifyProof(proof=proof,
                                          nonce=nonce2,
                                          attrs=attrs.encoded(),
                                          revealedAttrs=revealedAttrs)

    # The verification status should be false when using different nonce for
    # generating and verifying proof
    assert not verify_status


def testGenerateCredentialMustBePassedParameters(proverAndAttrs1, credDef1):
    prover, attrs = proverAndAttrs1

    # Manually override prover.U
    prover._U = {GVT.name: ''}

    # This should fail as we are not passing prover.U
    with pytest.raises(ValueError):
        presentationToken = getPresentationToken({GVT.name: credDef1},
                                             prover,
                                             attrs.encoded())

