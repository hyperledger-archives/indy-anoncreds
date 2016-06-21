from typing import Sequence

from anoncreds.protocol.attribute_repo import AttributeRepo
from anoncreds.protocol.credential_definition import CredentialDefinition
from anoncreds.protocol.utils import encodeAttrs


class Issuer:
    def __init__(self, id: str, attributeRepo: AttributeRepo):
        self.id = id
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

    def createCredential(self, proverId, name, version, U):
        credDef = self.getCredDef(name, version)
        attributes = self.attributeRepo.getAttributes(proverId)
        encAttrs = encodeAttrs(attributes)
        return credDef.generateCredential(U, encAttrs)

    def newCredDef(self, attrNames, name, version):
        credDef = CredentialDefinition(attrNames, name, version)

        self.addCredDef(credDef)
        return credDef


