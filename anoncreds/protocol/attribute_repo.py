from typing import Dict

from protocol.types import Attribs


class AttributeRepo:
    def __init__(self):
        self.attributes = {}    # type: Dict

    def getAttributes(self, proverId):
        return self.attributes.get(proverId)

    def addAttributes(self, proverId, attributes: Attribs):
        self.attributes[proverId] = attributes
