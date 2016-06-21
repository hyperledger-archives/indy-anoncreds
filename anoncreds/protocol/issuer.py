from typing import Sequence

from anoncreds.protocol.attribute_repo import AttributeRepo
from anoncreds.protocol.credential_definition import CredentialDefinition


class Issuer:
    def __init__(self, name: str, attributeRepo: AttributeRepo):
        self.credDefs = {}     # Dict[Tuple, CredentialDefinition]
        self.credDefsForAttribs = {}    # Dict[Tuple, List[Tuple]]
        self.attributeRepo = attributeRepo

    def getCredDef(self, name=None, version=None, attributes: Sequence[str]=None):
        if name and version:
            return self.credDefs[(name, version)]
        else:
            defs = self.credDefsForAttribs.get(tuple(sorted(attributes)))
            return defs[-1] if defs else None

    def addCredDef(self, credDef: CredentialDefinition):
        self.credDefs[(credDef.name, credDef.version)] = credDef

    def createCredential(self, proverId, name, version):
        attributes = self.attributeRepo.getAttributes(proverId)






