from anoncreds.protocol.prover import fourSquares
from anoncreds.protocol.types import GVT
from anoncreds.test.helper import getPresentationToken, getProver


def testPredicateCredentials(issuer1, proverAndAttrs1, verifier1):
    prover, attrs = proverAndAttrs1

    presentationToken = getPresentationToken({GVT.name: issuer1}, prover,
                                             attrs.encoded())

    nonce = verifier1.generateNonce

    revealedAttrs = ['name']
    predicate = {GVT.name: {'age': 18}}
    proof = prover.preparePredicateProof(credential=presentationToken,
                                         attrs=attrs.encoded(),
                                         revealedAttrs=revealedAttrs,
                                         nonce=nonce,
                                         predicate=predicate)

    verify_status = verifier1.verifyPredicateProof(proof=proof,
                                                   nonce=nonce,
                                                   attrs=attrs.encoded(),
                                                   revealedAttrs=revealedAttrs,
                                                   predicate=predicate)

    assert verify_status


def testQuadEquationLagranges():
    delta = 85
    u1, u2, u3, u4 = tuple(fourSquares(delta))
    print("u1: {0} u2: {1} u3: {2} u4: {3}".format(u1, u2, u3, u4))
    assert (u1 ** 2) + (u2 ** 2) + (u3 ** 2) + (u4 ** 2) == delta


