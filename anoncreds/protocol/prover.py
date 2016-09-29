from anoncreds.protocol.cred_def_store import CredDefStore
from anoncreds.protocol.issuer_key import IssuerKey
from anoncreds.protocol.issuer_key_store import IssuerKeyStore
from anoncreds.protocol.proof_builder import ProofBuilder
from anoncreds.protocol.verifier import Verifier


class Prover:
    def __init__(self, id, cds: CredDefStore, iks: IssuerKeyStore):
        self.id = id
        self.proofBuilders = {}     # Dict[ProofBuilder, ProofBuilder]
        self.cds = cds
        self.iks = iks

    def _getCredDef(self, uid):
        credDef = self.cds.fetch(uid)
        if not credDef:
            credDef = self.fetchCredentialDefinition(uid)
            self.credDefs[uid] = credDef
        return credDef

    def _getCred(self, issuer, cduid, credName, credVersion, U):
        key = issuer, cduid, credName, credVersion, U
        return self.fetchCredential(*key)

    def _initProofBuilder(self, cduid, ikuid, issuerId):

        credDef = self.cds.fetch(cduid)
        # DEPR
        # credDef = _getCredDef(issuer, attrNames)
        pk = self.iks.fetch(ikuid)
        pk = {issuerId: pk}
        proofBuilder = ProofBuilder(pk)
        self.proofBuilders[proofBuilder.id] = proofBuilder
        return proofBuilder

    def createProofBuilder(self, cduid, ikuid, issuer, attrNames, interactionId,
                           verifier, revealedAttrs):
        credDef = self._getCredDef(cduid)
        proofBuilder = self._initProofBuilder(cduid, ikuid, issuer.id)
        nonce = self.fetchNonce(interactionId, verifier)
        credential = self._getCred(issuer=issuer,
                                   cduid=cduid,
                                   credName=credDef.name,
                                   credVersion=credDef.version,
                                   U=proofBuilder.U[issuer.id])
        presentationToken = {
            issuer.id: (
            credential[0], credential[1],
            proofBuilder.vprime[issuer.id] + credential[2])
        }
        proofBuilder.setParams(presentationToken, revealedAttrs, nonce)
        return proofBuilder

    def fetchNonce(self, interactionId, verifier: Verifier):
        return verifier.generateNonce(interactionId)

    def fetchCredential(self, issuer, cduid, credName, credVersion, U):
        return issuer.createCred(self.id,
                                 cduid=cduid,
                                 name=credName,
                                 version=credVersion,
                                 U=U)
