import pytest

from anoncreds.protocol.proof import Proof
from anoncreds.test.helper import getPresentationToken, GVT
from anoncreds.protocol.verifier import verify_proof
from anoncreds.protocol import verifier


def testSingleProver(credDef1, attrNames1, proverAndAttrs1, credDefPk,
                     verifier1):
    proof, attrs = proverAndAttrs1
    assert len(attrs.encoded()[GVT.name]) == len(attrNames1)
    presentationToken = getPresentationToken({GVT.name: credDef1}, proof,
                                             attrs.encoded())
    nonce = verifier1.generateNonce(interactionId=1)
    # Prepare proof
    revealedAttrs = ['name']
    prf = Proof.prepareProof(proof.pk_i, proof.masterSecret,
                             credential=presentationToken,
                             attrs=attrs.encoded(),
                             revealedAttrs=revealedAttrs,
                             nonce=nonce)
    # Verify the proof
    # FIXME Unnecessary variable. Assert can be written here right away.
    verify_status = verify_proof(proof=prf,
                                 nonce=nonce,
                                 pk_i=credDefPk,
                                 attrs=attrs.encoded(),
                                 revealedAttrs=revealedAttrs)
    assert verify_status


# FIXME Code duplication. testMultipleProvers is essentially two times testSingleProver.
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
    proof1 = Proof.prepareProof(prover1.pk_i, prover1.masterSecret,
                                credential=presentationToken1,
                                  attrs=attrs1.encoded(),
                                  revealedAttrs=revealedAttrs,
                                  nonce=nonce1)
    # FIXME Bad indentation.
    proof2 = Proof.prepareProof(prover2.pk_i, prover2.masterSecret,
                                credential=presentationToken2,
                                  attrs=attrs2.encoded(),
                                  revealedAttrs=revealedAttrs,
                                  nonce=nonce2)
    # FIXME verify_proof is a static import.
    assert verifier.verify_proof(proof=proof1, nonce=nonce1,
                                 pk_i=credDefPk,
                                 attrs=attrs1.encoded(),
                                 revealedAttrs=revealedAttrs)
    assert verifier.verify_proof(proof=proof2, nonce=nonce2,
                                 pk_i=credDefPk,
                                 attrs=attrs2.encoded(),
                                 revealedAttrs=revealedAttrs)


# FIXME Code duplication with testSingleProver.
def testNonceShouldBeSame(credDef1, credDefPk, proverAndAttrs1, verifier1,
                          verifierMulti2):
    proof, attrs = proverAndAttrs1
    presentationToken = getPresentationToken({GVT.name: credDef1}, proof,
                                             attrs.encoded())
    nonce1 = verifier1.generateNonce(interactionId=4)
    nonce2 = verifierMulti2.generateNonce(interactionId=5)
    # Prepare proof
    revealedAttrs = ['name']
    prf = Proof.prepareProof(proof.pk_i, proof.masterSecret,
                             credential=presentationToken,
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
