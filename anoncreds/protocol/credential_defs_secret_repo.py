from abc import abstractmethod

from anoncreds.protocol.credential_definition import CredentialDefinitionInternal
from anoncreds.protocol.credential_defs_repo import CredentialDefsRepo
from anoncreds.protocol.types import CredDefId


class CredentialDefsSecretRepo:

    @abstractmethod
    def getCredentialDef(self, issuerId, credDefId: CredDefId):
        raise NotImplementedError

    @abstractmethod
    def addCredentialDef(self, issuerId, credDef: CredentialDefinitionInternal):
        raise NotImplementedError

    def __repr__(self):
        return str(self.__dict__)


class InMemoryCredentialDefsSecretRepo(CredentialDefinitionInternal):

    def __init__(self, credDefsRepo: CredentialDefsRepo):
        self.credDefs = {}              # Dict[Tuple, CredentialDefinition]
        self.credDefsForAttribs = {}    # Dict[Tuple, List]
        self.credDefsRepo = credDefsRepo

    def getCredentialDef(self, issuerId, credDefId: CredDefId):
        if credDefId.name and credDefId.version:
            return self.credDefs[(issuerId, credDefId.name, credDefId.version)]
        else:
            defs = self.credDefsForAttribs.get(self._getAttrsKey(issuerId, credDefId.attrNames))
            return defs[-1] if defs else None

    def addCredentialDef(self, issuerId, credDef: CredentialDefinitionInternal):
        self.credDefsRepo.addCredentialDef(issuerId, credDef.credentialDefinition)

        self.credDefs[(issuerId, credDef.name, credDef.version)] = credDef

        key = self._getAttrsKey(issuerId, credDef.attrNames)
        if key not in self.credDefsForAttribs:
            self.credDefsForAttribs[key] = []
        self.credDefsForAttribs[key].append(credDef)

    def _getAttrsKey(self, issuerId, attrNames):
        return tuple(issuerId, ) + tuple(sorted(attrNames))
