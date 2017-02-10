from anoncreds.protocol.globals import LARGE_E_START, ITERATIONS, DELTA
from anoncreds.protocol.primary.primary_proof_common import calcTeq, calcTge
from anoncreds.protocol.types import PrimaryEqualProof, \
    PrimaryPredicateGEProof, PrimaryProof, ID, ProofInput
from anoncreds.protocol.wallet.wallet import Wallet
from config.config import cmod


class PrimaryProofVerifier:
    def __init__(self, wallet: Wallet):
        self._wallet = wallet

    async def verify(self, proofInput: ProofInput, schemaKey, cHash,
                     primaryProof: PrimaryProof, allRevealedAttrs):
        cH = cmod.integer(cHash)
        THat = await self._verifyEquality(schemaKey, cH, primaryProof.eqProof,
                                          allRevealedAttrs)
        for geProof in primaryProof.geProofs:
            THat += await self._verifyGEPredicate(schemaKey, cH, geProof)

        return THat

    async def _verifyEquality(self, schemaKey, cH, proof: PrimaryEqualProof,
                              allRevealedAttrs):
        THat = []
        pk = await self._wallet.getPublicKey(ID(schemaKey))
        attrNames = (await self._wallet.getSchema(ID(schemaKey))).attrNames
        unrevealedAttrNames = set(attrNames) - set(proof.revealedAttrNames)

        T1 = calcTeq(pk, proof.Aprime, proof.e, proof.v,
                     proof.m, proof.m1, proof.m2,
                     unrevealedAttrNames)

        Rar = 1 % pk.N
        for attrName in proof.revealedAttrNames:
            Rar *= pk.R[str(attrName)] ** allRevealedAttrs[attrName]
        Rar *= proof.Aprime ** (2 ** LARGE_E_START)
        T2 = (pk.Z / Rar) ** (-1 * cH) % pk.N
        T = T1 * T2 % pk.N

        THat.append(T)
        return THat

    async def _verifyGEPredicate(self, schemaKey, cH,
                                 proof: PrimaryPredicateGEProof):
        pk = await self._wallet.getPublicKey(ID(schemaKey))
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
