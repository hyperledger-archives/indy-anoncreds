import pytest

from anoncreds.protocol.attribute_repo import AttributeRepo, \
    InMemoryAttributeRepo
from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.credential_definition import CredentialDefinition
from anoncreds.protocol.types import AttribsDef, AttribType
from anoncreds.protocol.verifier import Verifier
from anoncreds.temp_primes import P_PRIME1, Q_PRIME1, P_PRIME2, Q_PRIME2
from anoncreds.test.helper import getProofBuilder


@pytest.fixture(scope="module")
def gvtAttrRepo():
    attrRepo = InMemoryAttributeRepo()
    attrRepo.addAttributes('prover1', GVT.attribs())
    return attrRepo


@pytest.fixture(scope="module")
def gvt(gvtAttrRepo):
    return Issuer(GVT.name, gvtAttrRepo)


@pytest.fixture(scope="module")
def credDefPks(credDefs):
    credDefPks = {}
    for k, v in credDefs.items():
        credDefPks[k] = v.PK
    return credDefPks


@pytest.fixture(scope="module")
def gvtAttrNames():
    return GVT.getNames()


@pytest.fixture(scope="module")
def xyzAttrNames():
    return XYZCorp.getNames()


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
def gvtCredDef(gvtAttrNames, primes1):
    return CredentialDefinition(gvtAttrNames, **primes1)


@pytest.fixture(scope="module")
def xyzCredDef(xyzAttrNames, primes2):
    return CredentialDefinition(xyzAttrNames, **primes2)


@pytest.fixture(scope="module")
def credDefs(gvtCredDef, xyzCredDef):
    return {GVT.name: gvtCredDef, XYZCorp.name: xyzCredDef}


@pytest.fixture(scope="module")
def proofBuilderAndAttrs1(credDefPk):
    attribs = GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male')
    return getProofBuilder(attribs, credDefPk)


@pytest.fixture(scope="module")
def proofBuilderAndAttrs2(credDefPk):
    attribs = GVT.attribs(name='Jason Law', age=42, sex='male')
    return getProofBuilder(attribs, credDefPk)


@pytest.fixture(scope="module")
def proofBuilderAndAttrsForMultiple1(credDefPks):
    attribs = GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male')
    return getProofBuilder(attribs, credDefPks)


@pytest.fixture(scope="module")
def proofBuilderAndAttrsForMultiple2(credDefPks):
    attribs = XYZCorp.attribs(status='ACTIVE')
    return getProofBuilder(attribs, credDefPks)


@pytest.fixture(scope="module")
def proofBuilderAndAttrsMapForMultipleIssuers(credDefPks, gvtAttrList, xyzAttrList):
    attributeList = gvtAttrList + xyzAttrList
    return getProofBuilder(attributeList, credDefPks)


@pytest.fixture(scope="module")
def verifier1():
    return Verifier('verifier1')


@pytest.fixture(scope="module")
def verifierMulti1():
    return Verifier('verifierMulti1')


@pytest.fixture(scope="module")
def verifierMulti2():
    return Verifier('verifierMulti2')


GVT = AttribsDef('gvt',
                 [AttribType('name', encode=True),
                  AttribType('age', encode=False),
                  AttribType('sex', encode=True)])
XYZCorp = AttribsDef('xyz',
                     [AttribType('status', encode=True)])
NASEMP = GVT + XYZCorp