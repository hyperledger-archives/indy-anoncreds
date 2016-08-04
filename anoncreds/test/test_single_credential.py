import pytest

from anoncreds.protocol.proof_builder import ProofBuilder
from anoncreds.test.helper import getPresentationToken
from anoncreds.test.conftest import GVT
from anoncreds.protocol.verifier import verify_proof
from anoncreds.protocol import verifier


def testSingleProver(gvtCredDef, gvtAttrNames, proofBuilderAndAttrs1, credDefPk,
                     verifier1):
    proofBuilder, attrs = proofBuilderAndAttrs1
    assert len(attrs.encoded()[GVT.name]) == len(gvtAttrNames)
    presentationToken = getPresentationToken({GVT.name: gvtCredDef}, proofBuilder,
                                             attrs.encoded())
    nonce = verifier1.generateNonce(interactionId=1)
    # Prepare proof
    revealedAttrs = ['name']
    prf = ProofBuilder.prepareProof(proofBuilder.credDefPks, proofBuilder.masterSecret,
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
def testMultipleProvers(gvtCredDef, gvtAttrNames, proofBuilderAndAttrs1, proofBuilderAndAttrs2,
                        credDefPk, verifier1):
    proofBuilder1, attrs1 = proofBuilderAndAttrs1
    proofBuilder2, attrs2 = proofBuilderAndAttrs2
    assert len(attrs1.encoded()[GVT.name]) == len(gvtAttrNames)
    assert len(attrs2.encoded()[GVT.name]) == len(gvtAttrNames)
    presentationToken1 = getPresentationToken({GVT.name: gvtCredDef}, proofBuilder1,
                                              attrs1.encoded())
    presentationToken2 = getPresentationToken({GVT.name: gvtCredDef}, proofBuilder2,
                                              attrs2.encoded())
    nonce1 = verifier1.generateNonce(interactionId=2)
    nonce2 = verifier1.generateNonce(interactionId=3)
    # Prepare proofs
    revealedAttrs = ['name']
    proof1 = ProofBuilder.prepareProof(proofBuilder1.credDefPks, proofBuilder1.masterSecret,
                                       credential=presentationToken1,
                                       attrs=attrs1.encoded(),
                                       revealedAttrs=revealedAttrs,
                                       nonce=nonce1)
    # FIXME Bad indentation.
    proof2 = ProofBuilder.prepareProof(proofBuilder2.credDefPks, proofBuilder2.masterSecret,
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
def testNonceShouldBeSame(gvtCredDef, credDefPk, proofBuilderAndAttrs1, verifier1,
                          verifierMulti2):
    proofBuilder, attrs = proofBuilderAndAttrs1
    presentationToken = getPresentationToken({GVT.name: gvtCredDef}, proofBuilder,
                                             attrs.encoded())
    nonce1 = verifier1.generateNonce(interactionId=4)
    nonce2 = verifierMulti2.generateNonce(interactionId=5)
    # Prepare proof
    revealedAttrs = ['name']
    prf = ProofBuilder.prepareProof(proofBuilder.credDefPks, proofBuilder.masterSecret,
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


def testGenerateCredentialMustBePassedParameters(proofBuilderAndAttrs1, gvtCredDef):
    proof, attrs = proofBuilderAndAttrs1
    # Manually override prover.U
    proof._U = {GVT.name: ''}
    # This should fail as we are not passing prover.U
    with pytest.raises(ValueError):
        getPresentationToken({GVT.name: gvtCredDef}, proof,
                                                 attrs.encoded())
