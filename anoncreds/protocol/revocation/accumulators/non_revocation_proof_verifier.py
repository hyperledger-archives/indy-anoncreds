from typing import Sequence, Dict

from charm.toolbox.pairinggroup import PairingGroup

from anoncreds.protocol.revocation.accumulators.non_revocation_common import createTauListExpectedValues, \
    createTauListValues
from anoncreds.protocol.types import T, PublicData, \
    NonRevocProof, CredentialDefinition
from anoncreds.protocol.utils import bytes_to_ZR


class NonRevocationProofVerifier:
    def __init__(self, publicData: Dict[CredentialDefinition, PublicData]):
        self._groups = {x: PairingGroup(y.pkR.groupType) for x, y in publicData.items()}
        self._data = publicData

    @property
    def nonce(self):
        return self._nonce

    def verifyNonRevocation(self, credDef, cHash, nonRevocProof: NonRevocProof) -> Sequence[T]:
        pk = self._data[credDef].pkR
        accum = self._data[credDef].accum
        accumPk = self._data[credDef].pkAccum
        CProof = nonRevocProof.CProof
        XList = nonRevocProof.XList

        THatExpected = createTauListExpectedValues(pk, accum, accumPk, CProof)
        THatCalc = createTauListValues(pk, accum, XList, CProof)
        chNum_z = bytes_to_ZR(cHash, self._groups[credDef])

        return [(x ** chNum_z) * y for x, y in zip(THatExpected.asList(), THatCalc.asList())]
