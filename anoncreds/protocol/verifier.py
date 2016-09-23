from typing import Dict

from charm.core.math.integer import integer, randomBits

from anoncreds.protocol.credential_defs_repo import CredentialDefsRepo
from anoncreds.protocol.globals import LARGE_NONCE
from anoncreds.protocol.proof_verifier import ProofVerifier
from anoncreds.protocol.types import CredDefId

class Verifier:

    def __init__(self, id, credDefsRepo: CredentialDefsRepo):
        self.id = id
        self.credDefsRepo = credDefsRepo
        self._nonce = self._generateNonce()

    @property
    def nonce(self):
        return self._nonce

    def _generateNonce(self):
        return integer(randomBits(LARGE_NONCE))

    def createProofVerifier(self, credDefIds: Dict[str, CredDefId]):
        return ProofVerifier(self.credDefsRepo.getCredentialDefPKs(credDefIds), self._nonce)

    def __repr__(self):
        return str(self.__dict__)
