import pytest
from anoncreds.protocol.types import GVT
from anoncreds.test.helper import getProof, getPresentationToken
from anoncreds.protocol.proof import fourSquares


def testMainPredicate(credDef1, proverAndAttrs1, credDefPk,
                     verifier1):
    proof, attrs = proverAndAttrs1
    presentationToken = getPresentationToken({GVT.name: credDef1}, proof,
                                             attrs.encoded())
    nonce = verifier1.generateNonce(interactionId=1)
    revealedAttrs = ['name']
    predicate = {GVT.name: {'age': 18}}
    pproof = proof.preparePredicateProof(credential=presentationToken,
                                         attrs=attrs.encoded(),
                                         revealedAttrs=revealedAttrs,
                                         nonce=nonce,
                                         predicate=predicate)
    verify_status = verifier1.verifyPredicateProof(proof=pproof,
                                                  pk_i=credDefPk,
                                                  nonce=nonce,
                                                  attrs=attrs.encoded(),
                                                  revealedAttrs=revealedAttrs,
                                                  predicate=predicate)
    assert verify_status


def testPredicateMultipleIssuers(credDefs, credDefsPk, verifierMulti1,
                                 proverAndAttrsMapForMultipleIssuers):
    proof, attrs = proverAndAttrsMapForMultipleIssuers
    presentationToken = getPresentationToken(credDefs, proof,
                                             attrs.encoded())
    nonce = verifierMulti1.generateNonce(interactionId=1)
    revealedAttrs = ['name']
    predicate = {GVT.name: {'age': 18}}
    proof = proof.preparePredicateProof(credential=presentationToken,
                                         attrs=attrs.encoded(),
                                         revealedAttrs=revealedAttrs,
                                         nonce=nonce,
                                         predicate=predicate)
    verify_status = verifierMulti1.verifyPredicateProof(proof=proof,
                                                        nonce=nonce,
                                                        pk_i=credDefsPk,
                                                        attrs=attrs.encoded(),
                                                        revealedAttrs=revealedAttrs,
                                                        predicate=predicate)
    assert verify_status


def testNegativePredicateDeltaShouldFail(credDefs, verifierMulti1,
                                         proverAndAttrsMapForMultipleIssuers):
    proof, attrs = proverAndAttrsMapForMultipleIssuers
    presentationToken = getPresentationToken(credDefs, proof,
                                             attrs.encoded())
    nonce = verifierMulti1.generateNonce(interactionId=1)
    revealedAttrs = ['name']
    predicate = {GVT.name: {
        'age': 30}}  # This will result in a negative value of delta i.e. -5
    with pytest.raises(ValueError):
        prf = proof.preparePredicateProof(credential=presentationToken,
                                             attrs=attrs.encoded(),
                                             revealedAttrs=revealedAttrs,
                                             nonce=nonce,
                                             predicate=predicate)


def testQuadEquationLagranges():
    delta = 85
    u1, u2, u3, u4 = tuple(fourSquares(delta))
    print("u1: {0} u2: {1} u3: {2} u4: {3}".format(u1, u2, u3, u4))
    assert (u1 ** 2) + (u2 ** 2) + (u3 ** 2) + (u4 ** 2) == delta


def testQuadEquationLagrangesNegativeInt():
    delta = -5
    with pytest.raises(ValueError):
        u1, u2, u3, u4 = tuple(fourSquares(delta))
