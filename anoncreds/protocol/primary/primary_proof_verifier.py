from anoncreds.protocol.globals import LARGE_E_START, ITERATIONS, DELTA
from anoncreds.protocol.primary.primary_proof_common import calcTeq, calcTge
from anoncreds.protocol.types import PrimaryEqualProof, \
    PrimaryPredicateGEProof, PrimaryProof, ID
from anoncreds.protocol.wallet.wallet import Wallet
from config.config import cmod


class PrimaryProofVerifier:
    def __init__(self, wallet: Wallet):
        self._wallet = wallet

    async def verify(self, schemaId, cHash, primaryProof: PrimaryProof):
        cH = cmod.integer(cHash)
        THat = await self._verifyEquality(schemaId, cH, primaryProof.eqProof)
        for geProof in primaryProof.geProofs:
            THat += await self._verifyGEPredicate(schemaId, cH, geProof)

        return THat

    async def _verifyEquality(self, schemaId, cH, proof: PrimaryEqualProof):
        THat = []
        pk = await self._wallet.getPublicKey(ID(schemaId=schemaId))
        attrNames = (await self._wallet.getSchema(ID(schemaId=schemaId))).attrNames
        unrevealedAttrNames = set(attrNames) - set(proof.revealedAttrs.keys())

        T1 = calcTeq(pk, proof.Aprime, proof.e, proof.v,
                     proof.m, proof.m1, proof.m2,
                     unrevealedAttrNames)

        Rar = 1 % pk.N
        for attrName in proof.revealedAttrs.keys():
            Rar *= pk.R[str(attrName)] ** proof.revealedAttrs[str(attrName)]
        Rar *= proof.Aprime ** (2 ** LARGE_E_START)
        T2 = (pk.Z / Rar) ** (-1 * cH) % pk.N
        T = T1 * T2 % pk.N

        THat.append(T)
        return THat

    async def _verifyGEPredicate(self, schemaId, cH,
                                 proof: PrimaryPredicateGEProof):
        pk = await self._wallet.getPublicKey(ID(schemaId=schemaId))
        k, v = proof.predicate.attrName, proof.predicate.value

        TauList = calcTge(pk, proof.u, proof.r, proof.mj, proof.alpha, proof.T)

        for i in range(0, ITERATIONS):
            TT = proof.T[str(i)] ** (-1 * cH) % pk.N
            TauList[i] = TauList[i] * TT % pk.N
        TauList[ITERATIONS] = TauList[ITERATIONS] * (
            (proof.T[DELTA] * (pk.Z ** v)) ** (-1 * cH)) % pk.N
        TauList[ITERATIONS + 1] = (TauList[ITERATIONS + 1] * (
            proof.T[DELTA] ** (-1 * cH))) % pk.N

        return TauList
