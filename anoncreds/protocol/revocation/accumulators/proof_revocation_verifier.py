from functools import reduce
from typing import Dict

from charm.toolbox.pairinggroup import PairingGroup

from anoncreds.protocol.revocation.accumulators.proof_revocation_builder import ProofRevocationBuilder
from anoncreds.protocol.revocation.accumulators.types import RevocationPublicKey, Accumulator, RevocationProof
from anoncreds.protocol.utils import get_hash_hex, hex_hash_to_ZR


class ProofRevocationVerifier:
    def __init__(self, groups: Dict[str, PairingGroup], revocationPks: Dict[str, RevocationPublicKey], nonce):
        self._groups = groups
        self._revocationPks = revocationPks
        self._nonce = nonce

    @property
    def nonce(self):
        return self._nonce

    def verifyNonRevocation(self, issuerId, proof: RevocationProof, accum: Accumulator):
        CProof = proof.CList
        XList = proof.XList
        cHProof = proof.cH
        pk = self._revocationPks[issuerId]
        group = self._groups[issuerId]

        THatExpected = ProofRevocationBuilder.createTauListExpectedValues(pk, accum, CProof)
        THatCalc = ProofRevocationBuilder.createTauListValues(pk, accum, XList, CProof)
        chNum_z = hex_hash_to_ZR(cHProof, group)
        THat = [(x ** chNum_z) * y for x, y in zip(THatExpected.asList(), THatCalc.asList())]

        cHVerif = get_hash_hex(self._nonce, *reduce(lambda x, y: x + y, [THat, CProof.asList()]), group=group)

        return cHVerif == cHProof
