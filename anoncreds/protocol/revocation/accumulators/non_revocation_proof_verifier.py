from typing import Sequence

from anoncreds.protocol.globals import PAIRING_GROUP
from anoncreds.protocol.revocation.accumulators.non_revocation_common import createTauListExpectedValues, \
    createTauListValues
from anoncreds.protocol.types import T, NonRevocProof, ID
from anoncreds.protocol.utils import bytes_to_ZR
from anoncreds.protocol.wallet.wallet import Wallet
from config.config import cmod


class NonRevocationProofVerifier:
    def __init__(self, wallet: Wallet):
        self._wallet = wallet

    @property
    def nonce(self):
        return self._nonce

    def verifyNonRevocation(self, claimDefKey, cHash, nonRevocProof: NonRevocProof) -> Sequence[T]:
        pkR = self._wallet.getPublicKeyRevocation(ID(claimDefKey))
        accum = self._wallet.getAccumulator(ID(claimDefKey))
        accumPk = self._wallet.getPublicKeyAccumulator(ID(claimDefKey))

        CProof = nonRevocProof.CProof
        XList = nonRevocProof.XList

        group = cmod.PairingGroup(PAIRING_GROUP)  # super singular curve, 1024 bits
        THatExpected = createTauListExpectedValues(pkR, accum, accumPk, CProof)
        THatCalc = createTauListValues(pkR, accum, XList, CProof)
        chNum_z = bytes_to_ZR(cHash, group)

        return [(x ** chNum_z) * y for x, y in zip(THatExpected.asList(), THatCalc.asList())]
