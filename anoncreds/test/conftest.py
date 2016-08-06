import pytest

from anoncreds.protocol.attribute_repo import InMemoryAttrRepo
from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.credential_definition import CredentialDefinition
from anoncreds.protocol.types import AttribDef, AttribType
from anoncreds.protocol.verifier import Verifier
from anoncreds.temp_primes import P_PRIME1, Q_PRIME1, P_PRIME2, Q_PRIME2
from anoncreds.test.helper import getProofBuilder

GVT = AttribDef('gvt',
                [AttribType('name', encode=True),
                  AttribType('age', encode=False),
                  AttribType('sex', encode=True)])
XYZCorp = AttribDef('xyz',
                    [AttribType('status', encode=True)])
NASEMP = GVT + XYZCorp

@pytest.fixture(scope="module")
def gvtAttrRepo():
    attrRepo = InMemoryAttrRepo()
    attrRepo.addAttributes('prover1', GVT.attribs())
    return attrRepo


@pytest.fixture(scope="module")
def gvt(gvtAttrRepo):
    return Issuer(GVT.name, gvtAttrRepo)


@pytest.fixture(scope="module")
def gvtAttrNames():
    return GVT.attribNames()


@pytest.fixture(scope="module")
def xyzAttrNames():
    return XYZCorp.attribNames()


@pytest.fixture(scope="module")
def gvtCredDef(gvtAttrNames, primes1):
    return CredentialDefinition(gvtAttrNames, **primes1)


@pytest.fixture(scope="module")
def xyzCredDef(xyzAttrNames, primes2):
    return CredentialDefinition(xyzAttrNames, **primes2)


@pytest.fixture(scope="module")
def gvtCredDefPks(gvtCredDef):
    credDefPks = {}
    credDefPks[GVT.name] = gvtCredDef.PK
    return credDefPks

@pytest.fixture(scope="module")
def xyzCredDefPks(xyzCredDef):
    credDefPks = {}
    credDefPks[XYZCorp.name] = xyzCredDef.PK
    return credDefPks

@pytest.fixture(scope="module")
def gvtAndXyzCredDefs(gvtCredDef, xyzCredDef):
    return {GVT.name: gvtCredDef, XYZCorp.name: xyzCredDef}

@pytest.fixture(scope="module")
def gvtAndXyzCredDefPks(gvtAndXyzCredDefs):
    credDefPks = {}
    for k, v in gvtAndXyzCredDefs.items():
        credDefPks[k] = v.PK
    return credDefPks


@pytest.fixture(scope="module")
def primes1():
    return dict(p_prime=P_PRIME1, q_prime=Q_PRIME1)


@pytest.fixture(scope="module")
def primes2():
    return dict(p_prime=P_PRIME2, q_prime=Q_PRIME2)


@pytest.fixture(scope="module")
def gvtAttrList():
    return GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male')


@pytest.fixture(scope="module")
def xyzAttrList():
    return XYZCorp.attribs(status='ACTIVE')


@pytest.fixture(scope="module")
def credDefPk(gvtCredDef):
    """Return gvtCredDef's public key"""

    return {GVT.name: gvtCredDef.PK}


@pytest.fixture(scope="module")
def gvtProofBuilderWithProver1(credDefPk):
    attribs = GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male')
    return getProofBuilder(attribs, credDefPk)


@pytest.fixture(scope="module")
def gvtProofBuilderWithProver2(credDefPk):
    attribs = GVT.attribs(name='Jason Law', age=42, sex='male')
    return getProofBuilder(attribs, credDefPk)


@pytest.fixture(scope="module")
def proofBuilderWithGvtAttribs(gvtCredDefPks):
    attribs = GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male')
    return getProofBuilder(attribs, gvtCredDefPks)


@pytest.fixture(scope="module")
def proofBuilderWithXyzAttribs(xyzCredDefPks):
    attribs = XYZCorp.attribs(status='ACTIVE')
    return getProofBuilder(attribs, xyzCredDefPks)


@pytest.fixture(scope="module")
def proofBuilderWithGvtAndXyzAttribs(gvtAndXyzCredDefPks, gvtAttrList, xyzAttrList):
    attributeList = gvtAttrList + xyzAttrList
    return getProofBuilder(attributeList, gvtAndXyzCredDefPks)


@pytest.fixture(scope="module")
def verifier1():
    return Verifier('verifier1')


@pytest.fixture(scope="module")
def verifierMulti1():
    return Verifier('verifierMulti1')


@pytest.fixture(scope="module")
def verifierMulti2():
    return Verifier('verifierMulti2')

