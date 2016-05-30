import pytest

from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.utils import encodeAttrs
from anoncreds.protocol.verifier import Verifier
from anoncreds.protocol.prover import Prover


def getProver(attrs, pki):
    encodedAttrs = encodeAttrs(attrs)
    prover = Prover(pki)
    prover.set_attrs(encodedAttrs)
    return prover, encodedAttrs


def getPresentationToken(issuer, prover, encodedAttrs):
    presentationToken = {}
    for key, val in prover.U.items():
        A, e, vprimeprime = issuer.issue(prover.U[key], encodedAttrs)
        v = prover.vprime[key] + vprimeprime
        presentationToken[key] = {"A": A, "e": e, "v": v}
        return presentationToken


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

    prover, encodedAttrs = proverAndAttrs1
    assert len(encodedAttrs) == len(attrNames)

    presentationToken = getPresentationToken(issuer, *proverAndAttrs1)

    nonce = verifier.Nonce

    # Prepare proof
    revealedAttrs = ['name']
    proof = prover.prepare_proof(credential=presentationToken, attrs=encodedAttrs,
                                 revealedAttrs=revealedAttrs, nonce=nonce,
                                 encodedAttrsDict={"gvt": encodedAttrs})

    # Verify the proof
    verify_status = verifier.verify_proof(proof=proof, nonce=nonce,
                                          attrs=encodedAttrs,
                                          revealedAttrs=revealedAttrs,
                                          encodedAttrsDict={"gvt": encodedAttrs})

    assert verify_status


def testMultipleProvers(issuer, attrNames, proverAndAttrs1,
                        proverAndAttrs2, verifier):

    prover1, encodedAttrs1 = proverAndAttrs1
    prover2, encodedAttrs2 = proverAndAttrs2
    assert len(encodedAttrs1) == len(attrNames)
    assert len(encodedAttrs2) == len(attrNames)

    presentationToken1 = getPresentationToken(issuer, *proverAndAttrs1)
    presentationToken2 = getPresentationToken(issuer, *proverAndAttrs2)

    nonce1 = verifier.Nonce
    nonce2 = verifier.Nonce

    # Prepare proofs
    revealedAttrs = ['name']
    proof1 = prover1.prepare_proof(credential=presentationToken1, attrs=encodedAttrs1,
                                   revealedAttrs=revealedAttrs, nonce=nonce1,
                                   encodedAttrsDict={"gvt": encodedAttrs1})
    proof2 = prover2.prepare_proof(credential=presentationToken2, attrs=encodedAttrs2,
                                   revealedAttrs=revealedAttrs, nonce=nonce2,
                                   encodedAttrsDict={"gvt": encodedAttrs2})

    assert verifier.verify_proof(proof=proof1, nonce=nonce1,
                                 attrs=encodedAttrs1,
                                 revealedAttrs=revealedAttrs,
                                 encodedAttrsDict={"gvt": encodedAttrs1})
    assert verifier.verify_proof(proof=proof2, nonce=nonce2,
                                 attrs=encodedAttrs2,
                                 revealedAttrs=revealedAttrs,
                                 encodedAttrsDict={"gvt": encodedAttrs2})

