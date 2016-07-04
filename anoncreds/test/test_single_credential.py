import pytest

from anoncreds.protocol.types import GVT
from anoncreds.test.helper import getPresentationToken
from anoncreds.protocol.verifier import verify_proof
from protocol import verifier


def testSingleProver(credDef1, attrNames1, proverAndAttrs1, credDefPk,
                     verifier1):
    proof, attrs = proverAndAttrs1
    assert len(attrs.encoded()[GVT.name]) == len(attrNames1)
    presentationToken = getPresentationToken({GVT.name: credDef1}, proof,
                                             attrs.encoded())
    nonce = verifier1.generateNonce(interactionId=1)
    # Prepare proof
    revealedAttrs = ['name']
    prf = proof.prepareProof(credential=presentationToken,
                             attrs=attrs.encoded(),
                             revealedAttrs=revealedAttrs,
                             nonce=nonce)
    # Verify the proof
    verify_status = verify_proof(proof=prf,
                                 nonce=nonce,
                                 pk_i=credDefPk,
                                 attrs=attrs.encoded(),
                                 revealedAttrs=revealedAttrs)
    assert verify_status


def testMultipleProvers(credDef1, attrNames1, proverAndAttrs1, proverAndAttrs2,
                        credDefPk, verifier1):
    prover1, attrs1 = proverAndAttrs1
    prover2, attrs2 = proverAndAttrs2
    assert len(attrs1.encoded()[GVT.name]) == len(attrNames1)
    assert len(attrs2.encoded()[GVT.name]) == len(attrNames1)
    presentationToken1 = getPresentationToken({GVT.name: credDef1}, prover1,
                                              attrs1.encoded())
    presentationToken2 = getPresentationToken({GVT.name: credDef1}, prover2,
                                              attrs2.encoded())
    nonce1 = verifier1.generateNonce(interactionId=2)
    nonce2 = verifier1.generateNonce(interactionId=3)
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
    assert verifier.verify_proof(proof=proof1, nonce=nonce1,
                                 pk_i=credDefPk,
                                 attrs=attrs1.encoded(),
                                 revealedAttrs=revealedAttrs)
    assert verifier.verify_proof(proof=proof2, nonce=nonce2,
                                 pk_i=credDefPk,
                                 attrs=attrs2.encoded(),
                                 revealedAttrs=revealedAttrs)


def testNonceShouldBeSame(credDef1, credDefPk, proverAndAttrs1, verifier1,
                          verifierMulti2):
    proof, attrs = proverAndAttrs1
    presentationToken = getPresentationToken({GVT.name: credDef1}, proof,
                                             attrs.encoded())
    nonce1 = verifier1.generateNonce(interactionId=4)
    nonce2 = verifierMulti2.generateNonce(interactionId=5)
    # Prepare proof
    revealedAttrs = ['name']
    prf = proof.prepareProof(credential=presentationToken,
                             attrs=attrs.encoded(),
                             revealedAttrs=revealedAttrs,
                             nonce=nonce1)
    # Verify the proof
    verify_status = verify_proof(proof=prf,
                                 nonce=nonce2,
                                 pk_i=credDefPk,
                                 attrs=attrs.encoded(),
                                 revealedAttrs=revealedAttrs)
    # The verification status should be false when using different nonce for
    # generating and verifying proof
    assert not verify_status


def testGenerateCredentialMustBePassedParameters(proverAndAttrs1, credDef1):
    proof, attrs = proverAndAttrs1
    # Manually override prover.U
    proof._U = {GVT.name: ''}
    # This should fail as we are not passing prover.U
    with pytest.raises(ValueError):
        getPresentationToken({GVT.name: credDef1}, proof,
                                                 attrs.encoded())
