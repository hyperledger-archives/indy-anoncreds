import pytest

from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.verifier import Verifier
from anoncreds.protocol.utils import encodeAttrs
from anoncreds.test.helper import getPresentationToken, getProver


@pytest.fixture(scope="module")
def issuers(issuer, issuer2):
    return {"gvt": issuer, "ibm": issuer2}


@pytest.fixture(scope="module")
def issuersPk(issuers):
    pk_i = {}
    for k, v in issuers.items():
        pk_i[k] = v.PK
    return pk_i


@pytest.fixture(scope="module")
def attrNames2():
    return 'status',


@pytest.fixture(scope="module")
def issuer2(attrNames2):
    return Issuer(attrNames2)


@pytest.fixture(scope="module")
def proverAndAttrs2(issuersPk):
    attrs = {'status': 'ACTIVE'}
    return getProver(attrs, issuersPk)


@pytest.fixture(scope="module")
def verifier1(issuersPk):
    return Verifier(issuersPk)


@pytest.fixture(scope="module")
def verifier2(issuersPk):
    return Verifier(issuersPk)


def testMultipleCredentialSingleProof(issuers, proverAndAttrs, proverAndAttrs2, verifier1):
    prover, encodedAttrs1, attrs1 = proverAndAttrs
    prover, encodedAttrs2, attrs2 = proverAndAttrs2

    encodedAttrsDict = {"gvt": encodedAttrs1,
                        "ibm": encodedAttrs2}
    attrs = dict(list(attrs1.items()) + list(attrs2.items()))

    presentationToken = getPresentationToken(issuers, prover, encodedAttrsDict)

    nonce = verifier1.Nonce

    revealedAttrs = ['name']
    proof = prover.prepare_proof(credential=presentationToken, attrs=encodeAttrs(attrs),
                                 revealedAttrs=revealedAttrs, nonce=nonce,
                                 encodedAttrsDict=encodedAttrsDict)

    verify_status = verifier1.verify_proof(proof=proof, nonce=nonce,
                                          attrs=encodeAttrs(attrs),
                                          revealedAttrs=revealedAttrs,
                                          encodedAttrsDict=encodedAttrsDict)

    assert verify_status


def testMultipleCredentialMultipleVerifier(issuers, proverAndAttrs, proverAndAttrs2,
                                           verifier1, verifier2):
    prover, encodedAttrs1, attrs1 = proverAndAttrs
    prover, encodedAttrs2, attrs2 = proverAndAttrs2

    encodedAttrsDict = {"gvt": encodedAttrs1,
                        "ibm": encodedAttrs2}
    attrs = dict(list(attrs1.items()) + list(attrs2.items()))

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


