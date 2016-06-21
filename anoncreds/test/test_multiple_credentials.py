import pytest

from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.types import GVT, IBM
from anoncreds.protocol.verifier import Verifier
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
    attribs = GVT.attribs(name='Aditya Pratap Singh',
                          age=25,
                          sex='male')

    prover, attrs = getProver(attribs, issuerPk)

    return prover, attribs.encoded(), attrs


@pytest.fixture(scope="module")
def proverAndAttrs2(issuerPk):
    attribs = IBM.attribs(status='ACTIVE')

    prover, attrs = getProver(attribs, issuerPk)

    return prover, attribs.encoded(), attrs


@pytest.fixture(scope="module")
def verifier1(issuerPk):
    return Verifier(issuerPk)


@pytest.fixture(scope="module")
def verifier2(issuerPk):
    return Verifier(issuerPk)


def testMultipleCredentialSingleProof(issuers, proverAndAttrs1, proverAndAttrs2, verifier1):
    prover, encodedAttrs1, attrs1 = proverAndAttrs1
    prover, encodedAttrs2, attrs2 = proverAndAttrs2

    encodedAttrsDict = {"gvt": encodedAttrs1,
                        "ibm": encodedAttrs2}
    attrs = dict(list(attrs1.items()) + list(attrs2.items()))

    presentationToken = getPresentationToken(issuers, prover, encodedAttrsDict)

    nonce = verifier1.Nonce

    revealedAttrs = ['name']
    proof = prover.prepare_proof(credential=presentationToken, attrs=attrs.encoded(),
                                 revealedAttrs=revealedAttrs, nonce=nonce,
                                 encodedAttrsDict=encodedAttrsDict)

    verify_status = verifier1.verify_proof(proof=proof, nonce=nonce,
                                           attrs=attrs.encoded(),
                                           revealedAttrs=revealedAttrs,
                                           encodedAttrsDict=encodedAttrsDict)

    assert verify_status


def testMultipleCredentialMultipleVerifier(issuers, proverAndAttrs1, proverAndAttrs2,
                                           verifier1, verifier2):
    prover, encodedAttrs1, attrs1 = proverAndAttrs1
    prover, encodedAttrs2, attrs2 = proverAndAttrs2

    encodedAttrsDict = {"gvt": encodedAttrs1,
                        "ibm": encodedAttrs2}

    x = attrs1 + attrs2

    attrs = dict(list(attrs1.vals.items()) + list(attrs2.vals.items()))

    presentationToken = getPresentationToken(issuers, prover, encodedAttrsDict)

    nonce1 = verifier1.Nonce
    nonce2 = verifier2.Nonce

    revealedAttrs = ['name']
    proof1 = prover.prepare_proof(credential=presentationToken, attrs=encodeAttrs(attrs),
                                  revealedAttrs=revealedAttrs, nonce=nonce1,
                                  encodedAttrsDict=encodedAttrsDict)

    verify_status1 = verifier1.verify_proof(proof=proof1, nonce=nonce1,
                                            attrs=encodeAttrs(attrs),
                                            revealedAttrs=revealedAttrs,
                                            encodedAttrsDict=encodedAttrsDict)

    proof2 = prover.prepare_proof(credential=presentationToken, attrs=encodeAttrs(attrs),
                                  revealedAttrs=revealedAttrs, nonce=nonce2,
                                  encodedAttrsDict=encodedAttrsDict)

    verify_status2 = verifier1.verify_proof(proof=proof2, nonce=nonce2,
                                            attrs=encodeAttrs(attrs),
                                            revealedAttrs=revealedAttrs,
                                            encodedAttrsDict=encodedAttrsDict)

    assert verify_status1 and verify_status2


