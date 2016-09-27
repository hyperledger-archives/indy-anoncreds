from typing import Sequence

from charm.toolbox.pairinggroup import PairingGroup

from anoncreds.protocol.revocation.accumulators.non_revocation_proof_builder import NonRevocationProofBuilder
from anoncreds.protocol.types import T, PublicData, \
    NonRevocProof
from anoncreds.protocol.utils import bytes_to_ZR


class NonRevocationProofVerifier:
    def __init__(self, publicData: PublicData):
        self._groups = {x: PairingGroup(y.pkR.groupType) for x, y in publicData.items()}
        self._data = publicData

    @property
    def nonce(self):
        return self._nonce

    def verifyNonRevocation(self, issuerId, cHash, nonRevocProof: NonRevocProof) -> Sequence[T]:
        pk = self._data[issuerId].pkR
        accum = self._data[issuerId].accum
        accumPk = self._data[issuerId].pkAccum
        CProof = nonRevocProof.CProof
        XList = nonRevocProof.XList

        THatExpected = NonRevocationProofBuilder.createTauListExpectedValues(pk, accum, accumPk, CProof)
        THatCalc = NonRevocationProofBuilder.createTauListValues(pk, accum, XList, CProof)
        chNum_z = bytes_to_ZR(cHash, self._groups[issuerId])

        return [(x ** chNum_z) * y for x, y in zip(THatExpected.asList(), THatCalc.asList())]
