from typing import Sequence

from anoncreds.protocol.attribute_repo import AttributeRepo
from anoncreds.protocol.credential_definition import CredentialDefinition


class Issuer:
    def __init__(self, id, attributeRepo: AttributeRepo=None):
        self.id = id
        self.credDefs = {}     # Dict[Tuple, CredentialDefinition]
        self.credDefsForAttribs = {}    # Dict[Tuple, List]
        self.attributeRepo = attributeRepo

    def getCredDef(self, name=None, version=None, attributes: Sequence[str]=None):
        if name and version:
            return self.credDefs[(name, version)]
        else:
            defs = self.credDefsForAttribs.get(tuple(sorted(attributes)))
            return defs[-1] if defs else None

    def addCredDef(self, credDef: CredentialDefinition):
        self.credDefs[(credDef.name, credDef.version)] = credDef
        key = tuple(sorted(credDef.attrNames))
        if key not in self.credDefsForAttribs:
            self.credDefsForAttribs[key] = []
        self.credDefsForAttribs[key].append(credDef)

    # FIXME inconsistent naming. Rename to createCred.
    def createCredential(self, proverId, name, version, U):
        # This method works for one credDef only.
        credDef = self.getCredDef(name, version)
        attributes = self.attributeRepo.getAttributes(proverId)
        encAttrs = attributes.encoded()
        return CredentialDefinition.generateCredential(
            U, next(iter(encAttrs.values())), credDef.PK, credDef.p_prime,
            credDef.q_prime)

    def newCredDef(self, attrNames, name, version,
                   p_prime=None, q_prime=None, ip=None, port=None):
        credDef = CredentialDefinition(attrNames, name, version,
                                       p_prime, q_prime, ip, port)
        self.addCredDef(credDef)
        return credDef


