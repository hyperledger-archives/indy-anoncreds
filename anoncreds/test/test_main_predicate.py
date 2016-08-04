import pytest
from anoncreds.test.helper import getPresentationToken
from anoncreds.test.conftest import GVT
from anoncreds.protocol.proof_builder import fourSquares


def testMainPredicate(gvtCredDef, proofBuilderAndAttrs1, credDefPk,
                      verifier1):
    proofBuilder, attrs = proofBuilderAndAttrs1
    presentationToken = getPresentationToken({GVT.name: gvtCredDef}, proofBuilder,
                                             attrs.encoded())
    nonce = verifier1.generateNonce(interactionId=1)
    revealedAttrs = ['name']
    predicate = {GVT.name: {'age': 18}}
    proof = proofBuilder.preparePredicateProof(credential=presentationToken,
                                         attrs=attrs.encoded(),
                                         revealedAttrs=revealedAttrs,
                                         nonce=nonce,
                                         predicate=predicate)
    verify_status = verifier1.verifyPredicateProof(proof=proof,
                                                  pk_i=credDefPk,
                                                  nonce=nonce,
                                                  attrs=attrs.encoded(),
                                                  revealedAttrs=revealedAttrs,
                                                  predicate=predicate)
    assert verify_status


# FIXME Code duplication between testPredicateMultipleIssuers and testMainPredicate.
def testPredicateMultipleIssuers(credDefs, credDefPks, verifierMulti1,
                                 proofBuilderAndAttrsMapForMultipleIssuers):
    proofBuilder, attrs = proofBuilderAndAttrsMapForMultipleIssuers
    presentationToken = getPresentationToken(credDefs, proofBuilder,
                                             attrs.encoded())
    nonce = verifierMulti1.generateNonce(interactionId=1)
    revealedAttrs = ['name']
    predicate = {GVT.name: {'age': 18}}
    proof = proofBuilder.preparePredicateProof(credential=presentationToken,
                                         attrs=attrs.encoded(),
                                         revealedAttrs=revealedAttrs,
                                         nonce=nonce,
                                         predicate=predicate)
    verify_status = verifierMulti1.verifyPredicateProof(proof=proof,
                                                        nonce=nonce,
                                                        pk_i=credDefPks,
                                                        attrs=attrs.encoded(),
                                                        revealedAttrs=revealedAttrs,
                                                        predicate=predicate)
    assert verify_status


def testNegativePredicateDeltaShouldFail(credDefs, verifierMulti1,
                                         proofBuilderAndAttrsMapForMultipleIssuers):
    proofBuilder, attrs = proofBuilderAndAttrsMapForMultipleIssuers
    presentationToken = getPresentationToken(credDefs, proofBuilder,
                                             attrs.encoded())
    nonce = verifierMulti1.generateNonce(interactionId=1)
    revealedAttrs = ['name']
    predicate = {GVT.name: {
        'age': 30}}  # This will result in a negative value of delta i.e. -5
    with pytest.raises(ValueError):
        prf = proofBuilder.preparePredicateProof(credential=presentationToken,
                                          attrs=attrs.encoded(),
                                          revealedAttrs=revealedAttrs,
                                          nonce=nonce,
                                          predicate=predicate)


# FIXME These two tests don't belong in this file.
def testQuadEquationLagranges():
    delta = 85
    u1, u2, u3, u4 = tuple(fourSquares(delta))
    print("u1: {0} u2: {1} u3: {2} u4: {3}".format(u1, u2, u3, u4))
    assert (u1 ** 2) + (u2 ** 2) + (u3 ** 2) + (u4 ** 2) == delta


def testQuadEquationLagrangesNegativeInt():
    delta = -5
    with pytest.raises(ValueError):
        u1, u2, u3, u4 = tuple(fourSquares(delta))
