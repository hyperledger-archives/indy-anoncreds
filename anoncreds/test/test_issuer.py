import pytest
from anoncreds.protocol.credential_definition import CredentialDefinition


def testIssuerShouldBePassedAttributesList():
    # This test should fail to add credential definition as
    # Credential definition requires attributes name list
    with pytest.raises(ValueError):
        CredentialDefinition(1, list())
