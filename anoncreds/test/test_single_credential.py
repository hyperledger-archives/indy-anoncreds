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
    A, e, vprimeprime = issuer.issue(prover.U, encodedAttrs)
    v = prover.vprime + vprimeprime
    return {"encodedAttrs": encodedAttrs, "A": A, "e": e, "v": v}


@pytest.fixture(scope="module")
def attrLen():
    return 3


@pytest.fixture(scope="module")
def issuer(attrLen):
    # Create issuer
    return Issuer(attrLen)


@pytest.fixture(scope="module")
def issuerPk(issuer):
    # Return issuer's public key
    return issuer.PK


@pytest.fixture(scope="module")
def proverAndAttrs1(issuerPk):
    attrs = {'1': 'Aditya Pratap Singh', '2': '25', '3': 'male'}
    return getProver(attrs, issuerPk)


@pytest.fixture(scope="module")
def proverAndAttrs2(issuerPk):
    attrs = {'1': 'Jason Law', '2': '42', '3': 'male'}
    return getProver(attrs, issuerPk)


@pytest.fixture(scope="module")
def verifier(issuerPk):
    # Setup verifier
    return Verifier(issuerPk)


def testSingleProver(issuer, attrLen, proverAndAttrs1, verifier):

    prover, encodedAttrs = proverAndAttrs1
    assert len(encodedAttrs) == attrLen

    presentationToken = getPresentationToken(issuer, *proverAndAttrs1)

    nonce = verifier.Nonce

    # Prepare proof
    revealedAttrs = ['1']
    proof = prover.prepare_proof(presentationToken, revealedAttrs, nonce)

    # Verify the proof
    verify_status = verifier.verify_proof(proof, nonce, encodedAttrs)

    assert verify_status


def testMultipleProvers(issuer, attrLen, proverAndAttrs1,
                        proverAndAttrs2, verifier):

    prover1, encodedAttrs1 = proverAndAttrs1
    prover2, encodedAttrs2 = proverAndAttrs2
    assert len(encodedAttrs1) == attrLen
    assert len(encodedAttrs2) == attrLen

    presentationToken1 = getPresentationToken(issuer, *proverAndAttrs1)
    presentationToken2 = getPresentationToken(issuer, *proverAndAttrs2)

    nonce1 = verifier.Nonce
    nonce2 = verifier.Nonce

    # Prepare proofs
    revealedAttrs = ['1']
    proof1 = prover1.prepare_proof(presentationToken1, revealedAttrs, nonce1)
    proof2 = prover2.prepare_proof(presentationToken2, revealedAttrs, nonce2)

    assert verifier.verify_proof(proof1, nonce1, encodedAttrs1)
    assert verifier.verify_proof(proof2, nonce2, encodedAttrs2)

