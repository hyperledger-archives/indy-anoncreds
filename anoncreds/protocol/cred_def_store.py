from abc import abstractmethod

from anoncreds.protocol.credential_definition import CredentialDefinition


class CredDefStore:
    """
    A public credential definition store. Could be a public API, or a
    distributed ledger like Sovrin.
    """
    @abstractmethod
    def publishCredDef(self, cd: CredentialDefinition):
        pass

    @abstractmethod
    def fetchCredDef(self, uid) -> CredentialDefinition:
        pass
