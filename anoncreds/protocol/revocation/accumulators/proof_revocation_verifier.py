from functools import reduce

from charm.toolbox.pairinggroup import PairingGroup

from anoncreds.protocol.revocation.accumulators.proof_revocation_builder import ProofRevocationBuilder
from anoncreds.protocol.revocation.accumulators.types import RevocationPublicKey, Accumulator, RevocationProof
from anoncreds.protocol.utils import get_hash_hex, hex_hash_to_ZR


class ProofRevocationVerifier:
    def __init__(self, group: PairingGroup, pk: RevocationPublicKey, nonce):
        self._group = group
        self._pk = pk
        self._nonce = nonce

    @property
    def nonce(self):
        return self._nonce

    def verifyNonRevocation(self, proof: RevocationProof, accum: Accumulator):
        CProof = proof.CList
        XList = proof.XList
        cHProof = proof.cH

        THatExpected = ProofRevocationBuilder.createTauListExpectedValues(self._pk, accum, CProof)
        THatCalc = ProofRevocationBuilder.createTauListValues(self._pk, accum, XList, CProof)
        chNum_z = hex_hash_to_ZR(cHProof, self._group)
        THat = [(x ** chNum_z) * y for x, y in zip(THatExpected.asList(), THatCalc.asList())]

        cHVerif = get_hash_hex(self._nonce, *reduce(lambda x, y: x + y, [THat, CProof.asList()]), group=self._group)

        return cHVerif == cHProof
