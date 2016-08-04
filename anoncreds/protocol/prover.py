from anoncreds.protocol.credential_definition import CredentialDefinition
from anoncreds.protocol.proof_builder import ProofBuilder
from anoncreds.protocol.types import CredDefPublicKey


class Prover:
    def __init__(self, id):
        self.id = id
        self.credDefs = {}      # Dict[(issuer, id, attribute names), credentialDefinition]
        self.proofs = {}        # Dict[proof id, Proof]

    def _getCredDef(self, issuerId, attrNames):
        key = (issuerId, tuple(sorted(attrNames)))
        credDef = self.credDefs.get(key)
        if not credDef:
            credDef = self.fetchCredentialDefinition(*key)
            self.credDefs[key] = credDef
        return credDef

    def _getCred(self, issuerId, credName, credVersion, U):
        key = issuerId, credName, credVersion, U
        return self.fetchCredential(*key)

    @staticmethod
    def getPk(credDef: CredentialDefinition):
        credDef = credDef.get()
        R = credDef["keys"]["R"]
        R["0"] = credDef["keys"]["master_secret_rand"]
        return CredDefPublicKey(
            credDef["keys"]["N"],
            R,
            credDef["keys"]["S"],
            credDef["keys"]["Z"],
        )

    def _initProof(self, issuerId, attrNames):
        credDef = self._getCredDef(issuerId, attrNames)
        pk = self.getPk(credDef)
        pk = {issuerId: pk}
        proof = ProofBuilder(pk)
        self.proofs[proof.id] = proof
        return proof

    def createProof(self, issuerId, attrNames, verifierId,
                    encodedAttrs, revealedAttrs):
        credDef = self._getCredDef(issuerId, attrNames)
        proof = self._initProof(issuerId, attrNames)
        nonce = self.fetchNonce(verifierId)
        credential = self._getCred(issuerId, credDef.name,
                                  credDef.version, proof.U[issuerId])
        presentationToken = {
            issuerId: (
            credential[0], credential[1],
            proof.vprime[issuerId] + credential[2])
        }
        proof.setParams(encodedAttrs, presentationToken,
                        revealedAttrs, nonce)
        prf = ProofBuilder.prepareProof(proof.credDefPks, proof.masterSecret,
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
