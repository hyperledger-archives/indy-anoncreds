from typing import Dict


class AttributeRepo:
    def __init__(self):
        self.attributes = {}    # Dict[str, Dict]

    def getAttributes(self, proverId: str):
        self.attributes.get(proverId)

    def addAttributes(self, proverId: str, attributes: Dict):
        self.attributes[proverId] = attributes