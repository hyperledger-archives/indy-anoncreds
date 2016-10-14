from anoncreds.protocol.cred_def_store import CredDefStore
from anoncreds.protocol.globals import LARGE_VPRIME
from anoncreds.protocol.issuer_key import IssuerKey
from anoncreds.protocol.issuer_key_store import IssuerKeyStore
from anoncreds.protocol.proof_builder import ProofBuilder
from anoncreds.protocol.utils import generateMasterSecret
from anoncreds.protocol.verifier import Verifier
from config.config import cmod


class Prover:
    def __init__(self, id, cds: CredDefStore, iks: IssuerKeyStore):
        self.id = id
        self.proofBuilders = {}     # Dict[ProofBuilder, ProofBuilder]
        self.cds = cds
        self.iks = iks
        self.masterSecret = generateMasterSecret()
        self._vprimes = {}

    def getVPrimes(self, *keys):
        result = {}
        for key in keys:
            if key not in self._vprimes:
                self._vprimes[key] = cmod.randomBits(LARGE_VPRIME)
            result[key] = self._vprimes[key]
        return result

    def _getCredDef(self, uid):
        credDef = self.cds.fetchCredDef(uid)
        if not credDef:
            raise RuntimeError("Cred def not found for id {}".format(uid))
        return credDef

    def newProofBuilder(self, ikuid, issuerId):
        pk = self.iks.fetchIssuerKey(ikuid)
        pk = {issuerId: pk}
        vprime = self.getVPrimes(issuerId)
        proofBuilder = ProofBuilder(pk, self.masterSecret, vprime)
        self.proofBuilders[proofBuilder.id] = proofBuilder
        return proofBuilder
