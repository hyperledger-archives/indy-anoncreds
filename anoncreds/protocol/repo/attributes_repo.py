from abc import abstractmethod
from typing import Sequence

from anoncreds.protocol.prover import Prover
from anoncreds.protocol.types import Attribs, ClaimDefinitionKey


class AttributeRepo:
    @abstractmethod
    def getAttributes(self, claimDefKey: ClaimDefinitionKey, userId) -> Attribs:
        raise NotImplementedError

    @abstractmethod
    def getRevealedAttributes(self, claimDefKey: ClaimDefinitionKey, userId, revealedAttrs: Sequence[str]) -> Attribs:
        raise NotImplementedError

    @abstractmethod
    def getRevealedAttributesForProver(self, prover: Prover, revealedAttrs: Sequence[str]) -> Attribs:
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

    @abstractmethod
    def getRevealedAttributesForProver(self, prover: Prover, revealedAttrs: Sequence[str]) -> Attribs:
        if not len(revealedAttrs):
            return Attribs()

        claimDefs = prover.wallet.getAllClaimDef()

        attrsNamesForClaimDefs = {}
        foundRevealAttrs = set()
        for claimDef in claimDefs:
            attrsNamesForClaimDef = []
            for attrName in claimDef.attrNames:
                if attrName in revealedAttrs:
                    attrsNamesForClaimDef.append(attrName)
                    foundRevealAttrs.add(attrName)
            if len(attrsNamesForClaimDef):
                attrsNamesForClaimDefs[claimDef.getKey()] = attrsNamesForClaimDef

        revealedAttrs = set(revealedAttrs)
        if not foundRevealAttrs == revealedAttrs:
            raise ValueError("Unknown attributes: {}", revealedAttrs - foundRevealAttrs)

        attrs = Attribs()
        for claimDefKey, attrsNamesForClaimDef in attrsNamesForClaimDefs.items():
            attrsForClaimDef = self.getRevealedAttributes(claimDefKey, prover.id, attrsNamesForClaimDef)
            attrs = attrsForClaimDef if not attrs else attrs + attrsForClaimDef

        return attrs

    def addAttributes(self, claimDefKey: ClaimDefinitionKey, userId, attributes: Attribs):
        self.attributes[(claimDefKey, userId)] = attributes
