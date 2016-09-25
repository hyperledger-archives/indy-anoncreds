import pytest
from anoncreds.protocol.attribute_repo import InMemoryAttrRepo
from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.credential_definition import CredentialDefinition
from anoncreds.test.conftest import GVT


def testIssuerShouldBePassedAttributesList():
    attrRepo = InMemoryAttrRepo()
    attrRepo.addAttributes('prover1', GVT.attribs())

    issuer = Issuer(GVT.name, attrRepo)
    # This test should fail to add credential definition as
    # Credential definition requires attributes name list
    with pytest.raises(ValueError):
        CredentialDefinition(1, list())
