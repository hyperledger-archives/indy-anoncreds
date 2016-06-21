from anoncreds.protocol.proof import Proof


class Prover:
    def __init__(self):
        self.credDefs = {}      # Dict[(issuer, id, attribute names), credentialDefinition]
        self.credentials = {}   # Dict[(issuer id, name, version), List[credential]]
        self.proofs = {}        # Dict[proof id, Proof]

    def getCredentialDefinition(self, issuerId, attrNames):
        key = (issuerId, attrNames)
        credDef = self.credDefs.get(key)
        if not credDef:
            credDef = self.fetchCredentialDefinition(*key)
            self.credDefs[key] = credDef
        return credDef

    def getCredential(self, issuerId, credName, credVersion, U):
        key = issuerId, credName, credVersion, U
        cred = self.fetchCredential(*key)
        self.credentials[key] = cred
        return cred

    def initProofPreparation(self, name, version):
        credDef = self.getCredentialDefinition()
        pk = {
            "N": credDef["N"],
            "Z": credDef["Z"],
            "S": credDef["S"],
            "R": credDef[]
        }
        proof = Proof()
        self.proofs[proof.id] = proof

    def getNonce(self, proofId, verifierId):
        pass

    def prepareProof(self, nonce, revealedAttrs, encodedAttrs, credential):
        pass

    def sendProof(self, proof, verifierId):
        pass

    def fetchCredentialDefinition(self, issuerId, attributes):
        raise NotImplementedError

    def fetchCredential(self, issuerId, credName, credVersion, U):
        raise NotImplementedError
