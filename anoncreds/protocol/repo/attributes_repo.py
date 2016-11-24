from abc import abstractmethod
from typing import Sequence

from anoncreds.protocol.types import Attribs, ClaimDefinitionKey


class AttributeRepo:
    @abstractmethod
    def getAttributes(self, claimDefKey: ClaimDefinitionKey, userId) -> Attribs:
        raise NotImplementedError

    @abstractmethod
    def getRevealedAttributes(self, claimDefKey: ClaimDefinitionKey, userId, revealedAttrs: Sequence[str]) -> Attribs:
        raise NotImplementedError

    @abstractmethod
    def addAttributes(self, claimDefKey: ClaimDefinitionKey, userId, attributes: Attribs):
        raise NotImplementedError


class AttributeRepoInMemory(AttributeRepo):
    def __init__(self):
        self.attributes = {}

    def getAttributes(self, claimDefKey: ClaimDefinitionKey, userId) -> Attribs:
        return self.attributes.get((claimDefKey, userId))

    @abstractmethod
    def getRevealedAttributes(self, claimDefKey: ClaimDefinitionKey, userId, revealedAttrs: Sequence[str]) -> Attribs:
        attrs = self.attributes.get((claimDefKey, userId))
        revealedAttrValues = {revealedAttr: attrs[revealedAttr] for revealedAttr in revealedAttrs}
        return Attribs(attrs.credType, **revealedAttrValues)

    def addAttributes(self, claimDefKey: ClaimDefinitionKey, userId, attributes: Attribs):
        self.attributes[(claimDefKey, userId)] = attributes
