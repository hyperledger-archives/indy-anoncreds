from anoncreds.protocol.credential_definition import CredentialDefinition
from anoncreds.protocol.globals import KEYS, PK_R, MASTER_SEC_RAND, PK_N, PK_S, PK_Z
from anoncreds.protocol.proof_builder import ProofBuilder
from anoncreds.protocol.types import CredDefPublicKey
from anoncreds.protocol.verifier import Verifier


class Prover:
    def __init__(self, id):
        self.id = id
        self.credDefs = {}          # Dict[(issuer, attribute names), credentialDefinition]
        self.proofBuilders = {}     # Dict[ProofBuilder, ProofBuilder]

    def _getCredDef(self, issuer, attrNames):
        key = (issuer, tuple(sorted(attrNames)))
        credDef = self.credDefs.get(key)
        if not credDef:
            credDef = self.fetchCredentialDefinition(*key)
            self.credDefs[key] = credDef
        return credDef

    def _getCred(self, issuer, credName, credVersion, U):
        key = issuer, credName, credVersion, U
        return self.fetchCredential(*key)

    @staticmethod
    def getPk(credDef: CredentialDefinition):
        credDef = credDef.get()
        R = credDef[KEYS][PK_R]
        R["0"] = credDef[KEYS][MASTER_SEC_RAND]
        return CredDefPublicKey(
            credDef[KEYS][PK_N],
            R,
            credDef[KEYS][PK_S],
            credDef[KEYS][PK_Z],
        )

    def _initProofBuilder(self, issuer, attrNames):
        credDef = self._getCredDef(issuer, attrNames)
        pk = self.getPk(credDef)
        pk = {issuer.id: pk}
        proofBuilder = ProofBuilder(pk)
        self.proofBuilders[proofBuilder.id] = proofBuilder
        return proofBuilder

    def createProofBuilder(self, issuer, attrNames, interactionId, verifier,
                           revealedAttrs):
        credDef = self._getCredDef(issuer, attrNames)
        proofBuilder = self._initProofBuilder(issuer, attrNames)
        nonce = self.fetchNonce(interactionId, verifier)
        credential = self._getCred(issuer, credDef.name,
                                  credDef.version, proofBuilder.U[issuer.id])
        presentationToken = {
            issuer.id: (
            credential[0], credential[1],
            proofBuilder.vprime[issuer.id] + credential[2])
        }
        proofBuilder.setParams(presentationToken,
                        revealedAttrs, nonce)
        return proofBuilder

    def fetchNonce(self, interactionId, verifier: Verifier):
        return verifier.generateNonce(interactionId)

    def fetchCredentialDefinition(self, issuer, attributes):
        return issuer.getCredDef(attributes=attributes)

    def fetchCredential(self, issuer, credName, credVersion, U):
        return issuer.createCred(self.id, credName, credVersion, U)
