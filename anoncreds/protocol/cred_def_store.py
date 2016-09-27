from abc import abstractmethod

from anoncreds.protocol.credential_definition import CredentialDefinition


class CredDefStore:
    @abstractmethod
    def publish(self, cd: CredentialDefinition):
        pass

    @abstractmethod
    def fetch(self, uid) -> CredentialDefinition:
        pass
