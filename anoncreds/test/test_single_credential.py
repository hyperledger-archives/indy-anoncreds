import pytest

from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.verifier import Verifier
from anoncreds.test.helper import getPresentationToken, getProver


@pytest.fixture(scope="module")
def attrNames():
    return 'name', 'age', 'sex'


@pytest.fixture(scope="module")
def issuer(attrNames):
    # Create issuer
    return Issuer(attrNames)


@pytest.fixture(scope="module")
def issuerPk(issuer):
    # Return issuer's public key
    return {"gvt": issuer.PK}


@pytest.fixture(scope="module")
def proverAndAttrs1(issuerPk):
    attrs = {'name': 'Aditya Pratap Singh', 'age': '25', 'sex': 'male'}
    return getProver(attrs, issuerPk)


@pytest.fixture(scope="module")
def proverAndAttrs2(issuerPk):
    attrs = {'name': 'Jason Law', 'age': '42', 'sex': 'male'}
    return getProver(attrs, issuerPk)


@pytest.fixture(scope="module")
def verifier(issuerPk):
    # Setup verifier
    return Verifier(issuerPk)


def testSingleProver(issuer, attrNames, proverAndAttrs1, verifier):

    prover, encodedAttrs, attrs = proverAndAttrs1
    assert len(encodedAttrs) == len(attrNames)
    encodedAttrsDict = {"gvt": encodedAttrs}

    presentationToken = getPresentationToken({"gvt": issuer}, prover, encodedAttrsDict)

    nonce = verifier.Nonce

    # Prepare proof
    revealedAttrs = ['name']
    proof = prover.prepare_proof(credential=presentationToken, attrs=encodedAttrs,
                                 revealedAttrs=revealedAttrs, nonce=nonce,
                                 encodedAttrsDict=encodedAttrsDict)

    # Verify the proof
    verify_status = verifier.verify_proof(proof=proof, nonce=nonce,
                                          attrs=encodedAttrs,
                                          revealedAttrs=revealedAttrs,
                                          encodedAttrsDict=encodedAttrsDict)

    assert verify_status


def testMultipleProvers(issuer, attrNames, proverAndAttrs1,
                        proverAndAttrs2, verifier):

    prover1, encodedAttrs1, attrs1 = proverAndAttrs1
    prover2, encodedAttrs2, attrs2 = proverAndAttrs2
    assert len(encodedAttrs1) == len(attrNames)
    assert len(encodedAttrs2) == len(attrNames)
    encodedAttrsDict1 = {"gvt": encodedAttrs1}
    encodedAttrsDict2 = {"gvt": encodedAttrs2}

    presentationToken1 = getPresentationToken({"gvt": issuer}, prover1, encodedAttrsDict1)
    presentationToken2 = getPresentationToken({"gvt": issuer}, prover2, encodedAttrsDict2)

    nonce1 = verifier.Nonce
    nonce2 = verifier.Nonce

    # Prepare proofs
    revealedAttrs = ['name']
    proof1 = prover1.prepare_proof(credential=presentationToken1, attrs=encodedAttrs1,
                                   revealedAttrs=revealedAttrs, nonce=nonce1,
                                   encodedAttrsDict=encodedAttrsDict1)
    proof2 = prover2.prepare_proof(credential=presentationToken2, attrs=encodedAttrs2,
                                   revealedAttrs=revealedAttrs, nonce=nonce2,
                                   encodedAttrsDict=encodedAttrsDict2)

    assert verifier.verify_proof(proof=proof1, nonce=nonce1,
                                 attrs=encodedAttrs1,
                                 revealedAttrs=revealedAttrs,
                                 encodedAttrsDict=encodedAttrsDict1)
    assert verifier.verify_proof(proof=proof2, nonce=nonce2,
                                 attrs=encodedAttrs2,
                                 revealedAttrs=revealedAttrs,
                                 encodedAttrsDict=encodedAttrsDict2)

