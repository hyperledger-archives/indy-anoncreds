import pytest

from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.verifier import Verifier
from anoncreds.protocol.utils import encodeAttrs
from anoncreds.test.helper import getPresentationToken, getProver
from charm.core.math.integer import integer


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
    return Issuer(attrNames2, True,
                  p_prime=integer(161610459843908464667375821118575168226824282956978821640797520118616859558961395880196315322096458106037206290868757601849707785880099537257189258219310327562762606210985076067812502086850423537117076322748909902963854862506532321771281911610699500914980160157551242572791240516218628370968129992429972981803),
                  q_prime=integer(161493723223168517065151437243922053019267475361571371307287673539394775034094894440069890843406501007646183281736425436358728443271869768433133470245946207962338444877914886535613027325276708068934388710720146654092114476897070184618062196075578729368908143775530777165436283189882519306831269291698587939219))


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


