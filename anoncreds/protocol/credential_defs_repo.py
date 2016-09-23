from abc import abstractmethod
from typing import Dict

from anoncreds.protocol.credential_definition import CredentialDefinition
from anoncreds.protocol.types import CredDefId, CredDefPublicKey


class CredentialDefsRepo:

    @abstractmethod
    def getCredentialDef(self, issuerId, credDefId: CredDefId) -> CredentialDefinition:
        raise NotImplementedError

    @abstractmethod
    def getCredentialDefPKs(self, credDefIds: Dict[str, CredDefId]) -> Dict[str, CredDefPublicKey]:
        raise NotImplementedError

    @abstractmethod
    def addCredentialDef(self, issuerId, credDef: CredentialDefinition):
        raise NotImplementedError

    def __repr__(self):
        return str(self.__dict__)


class InMemoryCredentialDefsRepo(CredentialDefsRepo):

    def __init__(self):
        self.credDefs = {}              # Dict[Tuple, CredentialDefinition]
        self.credDefsForAttribs = {}    # Dict[Tuple, List]


    def getCredentialDef(self, issuerId, credDefId: CredDefId) -> CredentialDefinition:
        if credDefId.name and credDefId.version:
            return self.credDefs[(issuerId, credDefId.name, credDefId.version)]
        else:
            defs = self.credDefsForAttribs.get(self._getAttrsKey(issuerId, credDefId.attrNames))
            return defs[-1] if defs else None


    def getCredentialDefPKs(self, credDefIds: Dict[str, CredDefId]) -> Dict[str, CredDefPublicKey]:
        credDefPks = {}
        for key, val in credDefIds.items():
            credDefPks[key] = self.getCredentialDef(key, val).pk
        return credDefPks


    def addCredentialDef(self, issuerId, credDef: CredentialDefinition):
        self.credDefs[(issuerId, credDef.name, credDef.version)] = credDef

        key = self._getAttrsKey(issuerId, credDef.attrNames)
        if key not in self.credDefsForAttribs:
            self.credDefsForAttribs[key] = []
        self.credDefsForAttribs[key].append(credDef)

    def _getAttrsKey(self, issuerId, attrNames):
        return tuple(issuerId,) + tuple(sorted(attrNames))
