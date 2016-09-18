import pytest

from anoncreds.protocol.credential_definition import CredentialDefinitionInternal
from anoncreds.protocol.issuer import Issuer
from anoncreds.test.conftest import GVT


def testIssuerShouldBePassedAttributesList(attrRepo, credDefSecretRepo):
    issuer = Issuer(GVT.name, credDefSecretRepo, attrRepo)
    attrRepo.addAttributes('prover1', issuer.id, GVT.attribs())

    # This test should fail to add credential definition as
    # Credential definition requires attributes name list
    with pytest.raises(ValueError):
        CredentialDefinitionInternal(list())
