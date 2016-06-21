
class Prover:
    def __init__(self):
        self.credDefs = {}      # Dict[(issuer, id, attribute names), credentialDefinition]
        self.credentials = {}   # Dict[(issuer id, name, version), credential]
        self.proofs = {}        # Dict[proof id, (credential, nonce, revealed attrs, proof, encoded attributes)]

    def requestCredentialDefinition(self, issuerId, attributes):
        pass

    def requestCredential(self, issuerId, credName, credVersion):
        self.credentials.get((issuerId, credName, credVersion))

    def initProofPreparation(self, credential, credDef):
        pass

    def getNonce(self, proofId, verifierId):
        pass

    def prepareProof(self, nonce, revealedAttrs, encodedAttrs, credential):
        pass

    def sendProof(proof, verifierId):
        pass
