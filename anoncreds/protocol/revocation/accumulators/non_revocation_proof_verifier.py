from typing import Sequence

from anoncreds.protocol.globals import PAIRING_GROUP
from anoncreds.protocol.revocation.accumulators.non_revocation_common import \
    createTauListExpectedValues, \
    createTauListValues
from anoncreds.protocol.types import T, NonRevocProof, ID, ProofInput
from anoncreds.protocol.utils import int_to_ZR
from anoncreds.protocol.wallet.wallet import Wallet
from config.config import cmod


class NonRevocationProofVerifier:
    def __init__(self, wallet: Wallet):
        self._wallet = wallet

    async def verifyNonRevocation(self, proofInput: ProofInput, schemaKey,
                                  cHash, nonRevocProof: NonRevocProof) \
            -> Sequence[T]:
        if await self._wallet.shouldUpdateAccumulator(
                schemaId=ID(schemaKey),
                ts=proofInput.ts,
                seqNo=proofInput.seqNo):
            await self._wallet.updateAccumulator(schemaId=ID(schemaKey),
                                                 ts=proofInput.ts,
                                                 seqNo=proofInput.seqNo)

        pkR = await self._wallet.getPublicKeyRevocation(ID(schemaKey))
        accum = await self._wallet.getAccumulator(ID(schemaKey))
        accumPk = await self._wallet.getPublicKeyAccumulator(ID(schemaKey))

        CProof = nonRevocProof.CProof
        XList = nonRevocProof.XList

        group = cmod.PairingGroup(
            PAIRING_GROUP)  # super singular curve, 1024 bits
        THatExpected = createTauListExpectedValues(pkR, accum, accumPk, CProof)
        THatCalc = createTauListValues(pkR, accum, XList, CProof)
        chNum_z = int_to_ZR(cHash, group)

        return [(x ** chNum_z) * y for x, y in
                zip(THatExpected.asList(), THatCalc.asList())]
