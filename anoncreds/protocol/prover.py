from anoncreds.protocol.proof import Proof


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

    def initProof(self, issuerId, attrNames):
        credDef = self.getCredentialDefinition(issuerId, attrNames).get()
        R = credDef["keys"]["R"]
        R["0"] = credDef["keys"]["master_secret_rand"]
        # TODO: Remove this rk asap
        pk = { 'rk': {
            "N": credDef["keys"]["N"],
            "Z": credDef["keys"]["Z"],
            "S": credDef["keys"]["S"],
            "R": R
        }}
        proof = Proof(pk)
        self.proofs[proof.id] = proof
        return proof

    def createProof(self, issuerId, attrNames, verifierId, encodedAttrs, revealedAttrs):
        credDef = self.getCredentialDefinition(issuerId, attrNames)
        proof = self.initProof(issuerId, attrNames)
        nonce = self.fetchNonce(verifierId)
        # TODO: Remove this rk asap
        credential = self.getCredential(issuerId, credDef.name, credDef.version, proof.U['rk'])
        # TODO: Remove this rk asap
        proof.setParams(encodedAttrs, {'rk': credential}, revealedAttrs, nonce)
        prf = proof.prepare_proof()
        proof.prf = prf
        return proof

    def fetchNonce(self, verifierId):
        raise NotImplementedError

    def sendProof(self, issuerId, name, version, proof, verifierId):
        raise NotImplementedError

    def fetchCredentialDefinition(self, issuerId, attributes):
        raise NotImplementedError

    def fetchCredential(self, issuerId, credName, credVersion, U):
        raise NotImplementedError
