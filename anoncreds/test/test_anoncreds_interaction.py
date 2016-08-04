from anoncreds.protocol.attribute_repo import InMemoryAttributeRepo
from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.prover import Prover
from anoncreds.temp_primes import P_PRIME1, Q_PRIME1
from anoncreds.protocol.verifier import Verifier
from anoncreds.test.conftest import GVT

interactionId = 100
issuerId = GVT.name
proverId = '12'
verifierId = '13'


class TestIssuer(Issuer):
    pass


# FIXME Use Dependency Injection. Get rid of these test classes.
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
        return self.verifiers[verifierId].verify(issuerId, name, version,
                                                 proof.prf,
                                                 proof.nonce, proof.attrs,
                                                 proof.revealedAttrs)

    def fetchCredentialDefinition(self, issuerId, attributes):
        return self.issuers[issuerId].getCredDef(attributes=attributes)

    def fetchCredential(self, issuerId, credName, credVersion, U):
        return self.issuers[issuerId].createCred(self.id, credName,
                                                 credVersion, U)


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


# FIXME Interatction incomplete. Verifier must verify proof.
def testInteraction():
    attrRepo = InMemoryAttributeRepo()
    attrs = GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male')
    attrNames = tuple(attrs.keys())
    revealedAttrs = ["age", ]
    encodedAttrs = attrs.encoded()

    credName = "Profile"
    credVersion = "1.0"
    attrRepo.addAttributes(proverId, attrs)

    issuer = TestIssuer(issuerId, attrRepo)
    issuer.newCredDef(attrNames, credName, credVersion,
                      p_prime=P_PRIME1, q_prime=Q_PRIME1)
    prover = TestProver(proverId)
    verifier = TestVerifier(verifierId)

    prover.setVerifier(verifier)
    prover.setIssuer(issuer)
    verifier.setProver(prover)
    verifier.setIssuer(issuer)

    proof = prover.createProof(issuerId, attrNames, verifierId,
                               encodedAttrs, revealedAttrs)
    assert prover.sendProof(issuerId, credName, credVersion,
                            proof, verifierId)
