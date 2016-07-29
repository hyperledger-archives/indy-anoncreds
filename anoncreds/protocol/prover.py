from anoncreds.protocol.credential_definition import CredentialDefinition
from anoncreds.protocol.proof import Proof
from anoncreds.protocol.types import IssuerPublicKey


class Prover:
    def __init__(self, id):
        self.id = id
        self.credDefs = {}      # Dict[(issuer, id, attribute names), credentialDefinition]
        # self.credentials = {}   # Dict[(issuer id, name, version), List[credential]]
        self.proofs = {}        # Dict[proof id, Proof]

    def getCredentialDefinition(self, issuerId, attrNames):
        key = (issuerId, tuple(sorted(attrNames)))
        credDef = self.credDefs.get(key)
        if not credDef:
            credDef = self.fetchCredentialDefinition(*key)
            self.credDefs[key] = credDef
        return credDef

    def getCredential(self, issuerId, credName, credVersion, U):
        key = issuerId, credName, credVersion, U
        cred = self.fetchCredential(*key)
        # self.credentials[key] = cred
        return cred

    # FIXME CredDef is unnecessary in name as it's evident from only parameter.
    @staticmethod
    def getPkFromCredDef(credDef: CredentialDefinition):
        credDef = credDef.get()
        R = credDef["keys"]["R"]
        R["0"] = credDef["keys"]["master_secret_rand"]
        return IssuerPublicKey(
            credDef["keys"]["N"],
            R,
            credDef["keys"]["S"],
            credDef["keys"]["Z"],
        )

    def initProof(self, issuerId, attrNames):
        credDef = self.getCredentialDefinition(issuerId, attrNames)
        pk = self.getPkFromCredDef(credDef)
        pk = {issuerId: pk}
        proof = Proof(pk)
        self.proofs[proof.id] = proof
        return proof

    def createProof(self, issuerId, attrNames, verifierId,
                    encodedAttrs, revealedAttrs):
        credDef = self.getCredentialDefinition(issuerId, attrNames)
        proof = self.initProof(issuerId, attrNames)
        nonce = self.fetchNonce(verifierId)
        credential = self.getCredential(issuerId, credDef.name,
                                        credDef.version, proof.U[issuerId])
        presentationToken = {
            issuerId: (
            credential[0], credential[1],
            proof.vprime[issuerId] + credential[2])
        }
        proof.setParams(encodedAttrs, presentationToken,
                        revealedAttrs, nonce)
        prf = Proof.prepareProof(proof.pk_i, proof.masterSecret,
                                 credential=presentationToken,
                                 attrs=encodedAttrs,
                                 revealedAttrs=revealedAttrs, nonce=nonce)
        proof.prf = prf  # JN - Why is this required?
        return proof

    # FIXME Use abstract base class and get rid of these NotImplementedErrors
    def fetchNonce(self, verifierId):
        raise NotImplementedError

    def sendProof(self, issuerId, name, version, proof, verifierId):
        raise NotImplementedError

    def fetchCredentialDefinition(self, issuerId, attributes):
        raise NotImplementedError

    def fetchCredential(self, issuerId, credName, credVersion, U):
        raise NotImplementedError
