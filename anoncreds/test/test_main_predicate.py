import pytest

from anoncreds.test.helper import getPresentationToken, verifyPredicateProof
from anoncreds.test.conftest import GVT


def testMainPredicate(gvtCredDef, gvtCredDefPks, proofBuilderWithGvtAttribs,
                      verifier1):
    assert verifyPredicateProof({GVT.name: gvtCredDef}, gvtCredDefPks,
                proofBuilderWithGvtAttribs, ['name'], {GVT.name: {'age': 18}}, verifier1)


def testPredicateMultipleIssuers(gvtAndXyzCredDefs, gvtAndXyzCredDefPks,
                                 proofBuilderWithGvtAndXyzAttribs, verifierMulti1):
    assert verifyPredicateProof(gvtAndXyzCredDefs, gvtAndXyzCredDefPks, proofBuilderWithGvtAndXyzAttribs,
                ['name'], {GVT.name: {'age': 18}}, verifierMulti1)


def testNegativePredicateDeltaShouldFail(gvtAndXyzCredDefs, verifierMulti1,
                                         proofBuilderWithGvtAndXyzAttribs):
    proofBuilder, attrs = proofBuilderWithGvtAndXyzAttribs
    presentationToken = getPresentationToken(gvtAndXyzCredDefs, proofBuilder,
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


