import pytest
from anoncreds.protocol.types import GVT
from anoncreds.test.helper import getProver, getPresentationToken
from anoncreds.protocol.verifier import Verifier
from anoncreds.protocol.prover import fourSquares


def testMainPredicate(credDef1):
    credDef = credDef1
    issuerPk = {GVT.name: credDef.PK}
    verifier = Verifier(pk_i=issuerPk)

    attribs = GVT.attribs(name='Aditya Pratap Singh',
                          age=25,
                          sex='male')

    prover, attrs = getProver(attribs.encoded(), issuerPk)

    presentationToken = getPresentationToken({GVT.name: credDef}, prover, attrs)

    nonce = verifier.Nonce

    revealedAttrs = ['name']
    predicate = {GVT.name: {'age': 18}}
    proof = prover.preparePredicateProof(credential=presentationToken,
                                         attrs=attrs,
                                         revealedAttrs=revealedAttrs,
                                         nonce=nonce,
                                         predicate=predicate)

    verify_status = verifier.verifyPredicateProof(proof=proof,
                                                  nonce=nonce,
                                                  attrs=attrs,
                                                  revealedAttrs=revealedAttrs,
                                                  predicate=predicate)

    assert verify_status


def testPredicateMultipleIssuers(credDefs, verifierMulti1,
                                 proverAndAttrsMapForMultipleIssuers):

    prover, attrsMap = proverAndAttrsMapForMultipleIssuers

    presentationToken = getPresentationToken(credDefs, prover, attrsMap.encoded())

    nonce = verifierMulti1.Nonce

    revealedAttrs = ['name']
    predicate = {GVT.name: {'age': 18}}
    proof = prover.preparePredicateProof(credential=presentationToken, attrs=attrsMap.encoded(),
                                         revealedAttrs=revealedAttrs, nonce=nonce,
                                         predicate=predicate)

    verify_status = verifierMulti1.verifyPredicateProof(proof=proof, nonce=nonce, attrs=attrsMap.encoded(),
                                                        revealedAttrs=revealedAttrs, predicate=predicate)

    assert verify_status


def testNegativePredicateDeltaShouldFail(credDefs, verifierMulti1,
                                 proverAndAttrsMapForMultipleIssuers):

    prover, attrsMap = proverAndAttrsMapForMultipleIssuers

    presentationToken = getPresentationToken(credDefs, prover, attrsMap.encoded())

    nonce = verifierMulti1.Nonce

    revealedAttrs = ['name']
    predicate = {GVT.name: {'age': 30}}  # This will result in a negative value of delta i.e. -5

    with pytest.raises(ValueError):
        proof = prover.preparePredicateProof(credential=presentationToken, attrs=attrsMap.encoded(),
                                         revealedAttrs=revealedAttrs, nonce=nonce,
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
