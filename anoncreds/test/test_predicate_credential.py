import pytest
from anoncreds.test.helper import getProver, getPresentationToken
from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.verifier import Verifier
from anoncreds.protocol.prover import fourSquares
from functools import reduce


@pytest.fixture(scope="module")
def attrNames():
    return 'name', 'age', 'sex'


@pytest.fixture(scope="module")
def issuerPk(issuer):
    # Return issuer's public key
    return {"gvt": issuer.PK}


@pytest.fixture(scope="module")
def proverAndAttrs1(issuerPk):
    attrs = {'name': 'Aditya Pratap Singh', 'age': 25, 'sex': 'male'}
    return getProver(attrs, issuerPk)


@pytest.fixture(scope="module")
def issuer(attrNames):
    # Create issuer
    return Issuer(attrNames)


@pytest.fixture(scope="module")
def verifier(issuerPk):
    # Setup verifier
    return Verifier(issuerPk)

@pytest.mark.skip(reason="no way of currently testing this")
def testPredicateCredentials(issuer, proverAndAttrs1, verifier):
    prover, encodedAttrs, attrs = proverAndAttrs1
    encodedAttrsDict = {"gvt": encodedAttrs}

    presentationToken = getPresentationToken({"gvt": issuer}, prover, encodedAttrsDict)

    nonce = verifier.Nonce

    revealedAttrs = ['name']
    predicate = {'age': 18}
    proof = prover.preparePredicateProof(credential=presentationToken, attrs=encodedAttrs,
                                         revealedAttrs=revealedAttrs, nonce=nonce,
                                         predicate=predicate, encodedAttrsDict=encodedAttrsDict)

    verify_status = verifier.verify_proof(proof=proof, nonce=nonce,
                                          attrs=encodedAttrs, revealedAttrs=revealedAttrs,
                                          predicate=predicate, encodedAttrsDict=encodedAttrsDict)

    assert verify_status


def testQuadEquationLagranges():
    delta = 85
    u1, u2, u3, u4 = tuple(fourSquares(delta))
    print("u1: {0} u2: {1} u3: {2} u4: {3}".format(u1, u2, u3, u4))
    assert (u1 ** 2) + (u2 ** 2) + (u3 ** 2) + (u4 ** 2) == delta


def testFlattenObjectToList():
    Tau = {
        "Aprime": {
            "gvt": 57624956854567
        },
        "T": {
            "gvt": 789412326851265
        }
    }

    a = reduce(lambda x, y: y + x, Tau.items(), [])
