from abc import abstractmethod

from anoncreds.protocol.types import Attribs, SchemaKey


class AttributeRepo:
    @abstractmethod
    def getAttributes(self, claimDefKey: SchemaKey, userId) -> Attribs:
        raise NotImplementedError

    @abstractmethod
    def addAttributes(self, claimDefKey: SchemaKey, userId,
                      attributes: Attribs):
        raise NotImplementedError


class AttributeRepoInMemory(AttributeRepo):
    def __init__(self):
        self.attributes = {}

    def getAttributes(self, claimDefKey: SchemaKey, userId) -> Attribs:
        return self.attributes.get((claimDefKey, userId))

    def addAttributes(self, claimDefKey: SchemaKey, userId,
                      attributes: Attribs):
        self.attributes[(claimDefKey, userId)] = attributes
