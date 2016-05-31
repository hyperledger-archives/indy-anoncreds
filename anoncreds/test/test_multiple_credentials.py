import pytest

from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.verifier import Verifier
from anoncreds.protocol.utils import encodeAttrs
from anoncreds.test.helper import getPresentationToken, getProver


@pytest.fixture(scope="module")
def issuers(issuer1, issuer2):
    # Return issuer's public key
    return {"gvt": issuer1, "ibm": issuer2}


@pytest.fixture(scope="module")
def issuerPk(issuers):
    pk_i = {}
    for k, v in issuers.items():
        pk_i[k] = v.PK
    return pk_i


@pytest.fixture(scope="module")
def attrNames1():
    return 'name', 'age', 'sex'


@pytest.fixture(scope="module")
def attrNames2():
    return 'status',


@pytest.fixture(scope="module")
def issuer1(attrNames1):
    return Issuer(attrNames1)


@pytest.fixture(scope="module")
def issuer2(attrNames2):
    return Issuer(attrNames2)


@pytest.fixture(scope="module")
def proverAndAttrs1(issuerPk):
    attrs = {'name': 'Aditya Pratap Singh', 'age': '25', 'sex': 'male'}
    return getProver(attrs, issuerPk)


@pytest.fixture(scope="module")
def proverAndAttrs2(issuerPk):
    attrs = {'status': 'ACTIVE'}
    return getProver(attrs, issuerPk)


@pytest.fixture(scope="module")
def verifier(issuerPk):
    # Setup verifier
    return Verifier(issuerPk)


def testMultipleCredentialSingleProof(issuers, attrNames1, attrNames2,
                                      proverAndAttrs1, proverAndAttrs2, verifier):
    prover, encodedAttrs1, attrs1 = proverAndAttrs1
    prover, encodedAttrs2, attrs2 = proverAndAttrs2

    encodedAttrsDict = {"gvt": encodedAttrs1,
                        "ibm": encodedAttrs2}
    attrs = dict(list(attrs1.items()) + list(attrs2.items()))

    presentationToken = getPresentationToken(issuers, prover, encodedAttrsDict)

    nonce = verifier.Nonce

    revealedAttrs = ['name']
    proof = prover.prepare_proof(credential=presentationToken, attrs=encodeAttrs(attrs),
                                 revealedAttrs=revealedAttrs, nonce=nonce,
                                 encodedAttrsDict=encodedAttrsDict)

    verify_status = verifier.verify_proof(proof=proof, nonce=nonce,
                                          attrs=encodeAttrs(attrs),
                                          revealedAttrs=revealedAttrs,
                                          encodedAttrsDict=encodedAttrsDict)

    assert verify_status

