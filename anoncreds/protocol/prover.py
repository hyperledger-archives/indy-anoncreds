from typing import Dict

from charm.core.math.integer import randomBits, integer

from anoncreds.protocol.credential_defs_repo import CredentialDefsRepo
from anoncreds.protocol.globals import LARGE_MASTER_SECRET
from anoncreds.protocol.proof_builder import ProofBuilder
from anoncreds.protocol.types import CredDefId


class Prover:
    def __init__(self, id, credDefsRepo: CredentialDefsRepo):
        self.id = id
        self.credDefsRepo = credDefsRepo
        # Generate the master secret
        self._ms = integer(randomBits(LARGE_MASTER_SECRET))

    def createProofBuilder(self, credDefIds: Dict[str, CredDefId]):
        return ProofBuilder(self.credDefsRepo.getCredentialDefPKs(credDefIds),
                            self._ms)

    def __repr__(self):
        return str(self.__dict__)
