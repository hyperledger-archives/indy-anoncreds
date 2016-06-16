import pytest

from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.verifier import Verifier
from anoncreds.test.helper import getProver
from charm.core.math.integer import integer

@pytest.fixture(scope="session")
def attrNames():
    return 'name', 'age', 'sex'


@pytest.fixture(scope="session")
def issuer(attrNames):
    return Issuer(attrNames, True,
                  p_prime=integer(161610459843908464667375821118575168226824282956978821640797520118616859558961395880196315322096458106037206290868757601849707785880099537257189258219310327562762606210985076067812502086850423537117076322748909902963854862506532321771281911610699500914980160157551242572791240516218628370968129992429972981803),
                  q_prime=integer(161493723223168517065151437243922053019267475361571371307287673539394775034094894440069890843406501007646183281736425436358728443271869768433133470245946207962338444877914886535613027325276708068934388710720146654092114476897070184618062196075578729368908143775530777165436283189882519306831269291698587939219))


@pytest.fixture(scope="session")
def issuerPk(issuer):
    # Return issuer's public key
    return {"gvt": issuer.PK}


@pytest.fixture(scope="session")
def proverAndAttrs(issuerPk):
    attrs = {'name': 'Aditya Pratap Singh', 'age': '25', 'sex': 'male'}
    return getProver(attrs, issuerPk)


@pytest.fixture(scope="session")
def verifier(issuerPk):
    # Setup verifier
    return Verifier(issuerPk)