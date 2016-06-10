import pytest

from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.verifier import Verifier
from anoncreds.test.helper import getProver

@pytest.fixture(scope="session")
def attrNames():
    return 'name', 'age', 'sex'


@pytest.fixture(scope="session")
def issuer(attrNames):
    return Issuer(attrNames)


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