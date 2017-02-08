from abc import abstractmethod

from anoncreds.protocol.types import Attribs, SchemaKey


class AttributeRepo:
    @abstractmethod
    def getAttributes(self, schemaKey: SchemaKey, userId) -> Attribs:
        raise NotImplementedError

    @abstractmethod
    def addAttributes(self, schemaKey: SchemaKey, userId,
                      attributes: Attribs):
        raise NotImplementedError


class AttributeRepoInMemory(AttributeRepo):
    def __init__(self):
        self.attributes = {}

    def getAttributes(self, schemaKey: SchemaKey, userId) -> Attribs:
        return self.attributes.get((schemaKey, userId))

    def addAttributes(self, schemaKey: SchemaKey, userId,
                      attributes: Attribs):
        self.attributes[(schemaKey, userId)] = attributes
