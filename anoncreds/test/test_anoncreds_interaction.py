from anoncreds.protocol.attribute_repo import AttributeRepo
from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.prover import Prover
from anoncreds.protocol.utils import encodeAttrs
from anoncreds.protocol.verifier import Verifier


interactionId = 100
issuerId = 11
proverId = 12
verifierId = 13


class TestIssuer(Issuer):
    pass


class TestProver(Prover):
    def __init__(self, id):
        super().__init__(id)
        self.verifiers = {}
        self.issuers = {}

    def setIssuer(self, issuer):
        self.issuers[issuer.id] = issuer

    def setVerifier(self, verifier):
        self.verifiers[verifier.id] = verifier

    def fetchNonce(self, verifierId):
        verifier = self.verifiers[verifierId]
        nonce = verifier.generateNonce(interactionId)
        return nonce

    def sendProof(self, issuerId, name, version, proof, verifierId):
        self.verifiers[verifierId].verify(issuerId, name, version, proof.prf,
                                          proof.nonce, proof.attrs,
                                          proof.revealedAttrs)

    def fetchCredentialDefinition(self, issuerId, attributes):
        return self.issuers[issuerId].getCredDef(attributes=attributes)

    def fetchCredential(self, issuerId, credName, credVersion, U):
        return self.issuers[issuerId].createCredential(self.id, credName, credVersion, U)


class TestVerifier(Verifier):
    def __init__(self, id):
        super().__init__(id)
        self.provers = {}
        self.issuers = {}

    def setIssuer(self, issuer):
        self.issuers[issuer.id] = issuer

    def setProver(self, prover):
        self.provers[prover.id] = prover

    def fetchCredDef(self, issuerId, name, version):
        return self.issuers[issuerId].getCredDef(name=name, version=version)

    def sendStatus(self, proverId, status):
        raise NotImplementedError


def testInteraction():
    attrRepo = AttributeRepo()
    attrs = {'name': 'Aditya Pratap Singh', 'age': '25', 'sex': 'male'}
    attrNames = tuple(attrs.keys())
    revealedAttrs = ["age", ]
    encodedAttrs = encodeAttrs(attrs)

    credName = "Profile"
    credVersion = "1.0"
    attrRepo.addAttributes(proverId, attrs)

    issuer = TestIssuer(issuerId, attrRepo)
    issuer.newCredDef(attrNames, credName, credVersion)
    prover = TestProver(proverId)
    verifier = TestVerifier(verifierId)

    prover.setVerifier(verifier)
    prover.setIssuer(issuer)
    verifier.setProver(prover)
    verifier.setIssuer(issuer)

    proof = prover.createProof(issuerId, attrNames, verifierId, encodedAttrs,
                             revealedAttrs)
    prover.sendProof(issuerId, credName, credVersion, proof, verifierId)
