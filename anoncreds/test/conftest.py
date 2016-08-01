import pytest

from anoncreds.protocol.attribute_repo import AttributeRepo, \
    InMemoryAttributeRepo
from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.credential_definition import CredentialDefinition
from anoncreds.protocol.verifier import Verifier
from anoncreds.temp_primes import P_PRIME, Q_PRIME, P_PRIME2, Q_PRIME2
from anoncreds.test.helper import getProof, GVT, XYZCorp


# FIXME All fixtures here deserve better names. I wrote my suggestions inside the methods.
@pytest.fixture(scope="module")
def attrRepo1():
    # FIXME gvtAttrRepo
    attrRepo = InMemoryAttributeRepo()
    attrRepo.addAttributes('prover1', GVT.attribs())
    return attrRepo


@pytest.fixture(scope="module")
def issuer1(attrRepo1):
    # FIXME gvt
    return Issuer(GVT.name, attrRepo1)


@pytest.fixture(scope="module")
def credDefsPk(credDefs):
    # FIXME 
    pk_i = {}
    for k, v in credDefs.items():
        pk_i[k] = v.PK
    return pk_i


@pytest.fixture(scope="module")
def attrNames1():
    # FIXME gvtAttrNames
    return GVT.getNames()


@pytest.fixture(scope="module")
def attrNames2():
    # FIXME xyzAttrNames
    return XYZCorp.getNames()


@pytest.fixture(scope="module")
def primes1():
    return dict(p_prime=P_PRIME, q_prime=Q_PRIME)


@pytest.fixture(scope="module")
def primes2():
    return dict(p_prime=P_PRIME2, q_prime=Q_PRIME2)


@pytest.fixture(scope="module")
def attrsList1():
    # FIXME gvtAttrList or attrListGVT
    return GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male')


@pytest.fixture(scope="module")
def attrsList2():
    return XYZCorp.attribs(status='ACTIVE')


@pytest.fixture(scope="module")
def credDefPk(credDef1):
    """Return credDef1's public key"""
    return {GVT.name: credDef1.PK}


@pytest.fixture(scope="module")
def credDef1(attrNames1, primes1):
    return CredentialDefinition(attrNames1, **primes1)


@pytest.fixture(scope="module")
def credDef2(attrNames2, primes2):
    return CredentialDefinition(attrNames2, **primes2)


@pytest.fixture(scope="module")
def credDefs(credDef1, credDef2):
    return {GVT.name: credDef1, XYZCorp.name: credDef2}


@pytest.fixture(scope="module")
def proverAndAttrs1(credDefPk):
    attribs = GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male')
    # FIXME Replace the following 2 lines by `return getProof(attribs, credDefsPk)`
    proof, attrs = getProof(attribs, credDefPk)
    return proof, attrs


@pytest.fixture(scope="module")
def proverAndAttrs2(credDefPk):
    attribs = GVT.attribs(name='Jason Law', age=42, sex='male')
    # FIXME Replace the following 2 lines by `return getProof(attribs, credDefsPk)`
    proof, attrs = getProof(attribs, credDefPk)
    return proof, attrs


@pytest.fixture(scope="module")
def proverAndAttrsForMultiple1(credDefsPk):
    attribs = GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male')
    # FIXME Replace the following 2 lines by `return getProof(attribs, credDefsPk)`
    proof, attrs = getProof(attribs, credDefsPk)
    return proof, attrs


@pytest.fixture(scope="module")
def proverAndAttrsForMultiple2(credDefsPk):
    attribs = XYZCorp.attribs(status='ACTIVE')
    # FIXME Replace the following 2 lines by `return getProof(attribs, credDefsPk)`
    proof, attrs = getProof(attribs, credDefsPk)
    return proof, attrs


@pytest.fixture(scope="module")
def proverAndAttrsMapForMultipleIssuers(credDefsPk, attrsList1, attrsList2):
    attributeList = attrsList1 + attrsList2
    # FIXME Replace the following 2 lines by `return getProof(attributeList, credDefsPk)`
    proof, attrs = getProof(attributeList, credDefsPk)
    return proof, attrs


@pytest.fixture(scope="module")
def verifier1():
    return Verifier('verifier1')


@pytest.fixture(scope="module")
def verifierMulti1():
    return Verifier('verifierMulti1')


@pytest.fixture(scope="module")
def verifierMulti2():
    return Verifier('verifierMulti2')
