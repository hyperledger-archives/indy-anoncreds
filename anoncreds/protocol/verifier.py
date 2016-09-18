from typing import Dict

from anoncreds.protocol.credential_defs_repo import CredentialDefsRepo
from anoncreds.protocol.proof_verifier import ProofVerifier
from anoncreds.protocol.types import CredDefId


class Verifier:

    def __init__(self, id, credDefsRepo: CredentialDefsRepo):
        self.id = id
        self.credDefsRepo = credDefsRepo


    def createProofVerifier(self, credDefIds: Dict[str, CredDefId]):
        return ProofVerifier(self.credDefsRepo.getCredentialDefPKs(credDefIds))
