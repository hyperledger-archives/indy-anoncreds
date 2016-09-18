from abc import abstractmethod
from typing import Dict

from anoncreds.protocol.types import Attribs


class AttrRepo:
    @abstractmethod
    def getAttributes(self, proverId, issuerId) -> Attribs:
        raise NotImplementedError

    @abstractmethod
    def addAttributes(self, proverId, issuerId, attributes: Attribs):
        raise NotImplementedError


class InMemoryAttrRepo(AttrRepo):
    def __init__(self):
        self.attributes = {}    # type: Dict

    def getAttributes(self, proverId, issuerId) -> Attribs:
        return self.attributes.get((proverId, issuerId))

    def addAttributes(self, proverId, issuerId, attributes: Attribs):
        self.attributes[(proverId, issuerId)] = attributes

