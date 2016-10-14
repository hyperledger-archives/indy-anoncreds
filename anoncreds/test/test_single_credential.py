import pytest

from anoncreds.test.helper import getPresentationToken, verifyProof, prepareProofAndVerify
from anoncreds.test.conftest import GVT


def testSingleProver(gvtCredDef,
                     gvtIssuerPk,
                     gvtAndXyzIssuerSecretKeys,
                     gvtAttrNames,
                     proofBuilderWithGvtAttribs,
                     verifier1):
    assert verifyProof({GVT.name: gvtCredDef},
                       gvtIssuerPk,
                       gvtAndXyzIssuerSecretKeys,
                       gvtAttrNames,
                       proofBuilderWithGvtAttribs,
                       ['name'],
                       verifier1)


def testMultipleProvers(gvtCredDef,
                        gvtIssuerPk,
                        gvtAttrNames,
                        gvtAndXyzIssuerSecretKeys,
                        gvtProofBuilderWithProver1,
                        gvtProofBuilderWithProver2,
                        verifier1):
    assert verifyProof({GVT.name: gvtCredDef},
                       gvtIssuerPk,
                       gvtAndXyzIssuerSecretKeys,
                       gvtAttrNames,
                       gvtProofBuilderWithProver1,
                       ['name'],
                       verifier1)

    assert verifyProof({GVT.name: gvtCredDef},
                       gvtIssuerPk,
                       gvtAndXyzIssuerSecretKeys,
                       gvtAttrNames,
                       gvtProofBuilderWithProver2,
                       ['name'],
                       verifier1)


def testNonceShouldBeSame(gvtCredDef,
                          gvtIssuerPk,
                          gvtAndXyzIssuerSecretKeys,
                          gvtProofBuilderWithProver1,
                          verifier1,
                          verifierMulti2):
    proofBuilder, attrs = gvtProofBuilderWithProver1
    nonce1 = verifier1.generateNonce(interactionId=4)
    nonce2 = verifierMulti2.generateNonce(interactionId=5)

    assert not prepareProofAndVerify({GVT.name: gvtCredDef},
                                     gvtIssuerPk,
                                     gvtAndXyzIssuerSecretKeys,
                                     proofBuilder,
                                     attrs,
                                     ['name'],
                                     nonce1,
                                     nonce2)


def testGenerateCredentialMustBePassedParameters(proofBuilderWithGvtAttribs,
                                                 gvtCredDef,
                                                 gvtIssuerPk,
                                                 gvtAndXyzIssuerSecretKeys):
    gvtProofBuilder, attrs = proofBuilderWithGvtAttribs
    # Manually override prover.U
    gvtProofBuilder._U = {GVT.name: ''}
    # This should fail as we are not passing prover.U
    with pytest.raises(ValueError):
        getPresentationToken({GVT.name: gvtCredDef},
                             gvtIssuerPk,
                             gvtAndXyzIssuerSecretKeys,
                             gvtProofBuilder,
                             attrs.encoded())
