import pytest

from anoncreds.test.helper import getPresentationToken, verifyProof, prepareProofAndVerify
from anoncreds.test.conftest import GVT


def testSingleProver(gvtCredDef, gvtAttrNames, proofBuilderWithGvtAttribs, gvtCredDefPks,
                     verifier1):
    assert verifyProof({GVT.name: gvtCredDef}, gvtCredDefPks, gvtAttrNames, proofBuilderWithGvtAttribs,
                ['name'], verifier1)


def testMultipleProvers(gvtCredDef, gvtAttrNames, gvtCredDefPks,
                        gvtProofBuilderWithProver1, gvtProofBuilderWithProver2,
                        verifier1):
    assert verifyProof({GVT.name: gvtCredDef}, gvtCredDefPks, gvtAttrNames, gvtProofBuilderWithProver1,
                ['name'], verifier1)

    assert verifyProof({GVT.name: gvtCredDef}, gvtCredDefPks, gvtAttrNames, gvtProofBuilderWithProver2,
                ['name'], verifier1)


def testNonceShouldBeSame(gvtCredDef, gvtCredDefPks,
                          gvtProofBuilderWithProver1, verifier1,
                          verifierMulti2):
    proofBuilder, attrs = gvtProofBuilderWithProver1
    nonce1 = verifier1.generateNonce(interactionId=4)
    nonce2 = verifierMulti2.generateNonce(interactionId=5)

    assert not prepareProofAndVerify({GVT.name: gvtCredDef}, gvtCredDefPks, proofBuilder,
                          attrs, ['name'], nonce1, nonce2)


def testGenerateCredentialMustBePassedParameters(proofBuilderWithGvtAttribs, gvtCredDef):
    gvtProofBuilder, attrs = proofBuilderWithGvtAttribs
    # Manually override prover.U
    gvtProofBuilder._U = {GVT.name: ''}
    # This should fail as we are not passing prover.U
    with pytest.raises(ValueError):
        getPresentationToken({GVT.name: gvtCredDef}, gvtProofBuilder,
                                                 attrs.encoded())
