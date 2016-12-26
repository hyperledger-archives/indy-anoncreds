from abc import abstractmethod

from anoncreds.protocol.types import Attribs, ClaimDefinitionKey


class AttributeRepo:
    @abstractmethod
    def getAttributes(self, claimDefKey: ClaimDefinitionKey, userId) -> Attribs:
        raise NotImplementedError

    @abstractmethod
    def addAttributes(self, claimDefKey: ClaimDefinitionKey, userId,
                      attributes: Attribs):
        raise NotImplementedError


class AttributeRepoInMemory(AttributeRepo):
    def __init__(self):
        self.attributes = {}

    def getAttributes(self, claimDefKey: ClaimDefinitionKey, userId) -> Attribs:
        return self.attributes.get((claimDefKey, userId))

    def addAttributes(self, claimDefKey: ClaimDefinitionKey, userId,
                      attributes: Attribs):
        self.attributes[(claimDefKey, userId)] = attributes
