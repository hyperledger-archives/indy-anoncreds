from typing import Dict


class AttributeRepo:
    def __init__(self):
        self.attributes = {}    # Dict

    def getAttributes(self, proverId):
        return self.attributes.get(proverId)

    def addAttributes(self, proverId, attributes: Dict):
        self.attributes[proverId] = attributes