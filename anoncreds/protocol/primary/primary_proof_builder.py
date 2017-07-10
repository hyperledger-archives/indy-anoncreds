from typing import Sequence, Dict

from anoncreds.protocol.globals import LARGE_VPRIME, LARGE_MVECT, LARGE_E_START, \
    LARGE_ETILDE, \
    LARGE_VTILDE, LARGE_UTILDE, LARGE_RTILDE, LARGE_ALPHATILDE, ITERATIONS, \
    DELTA
from anoncreds.protocol.primary.primary_proof_common import calcTge, calcTeq
from anoncreds.protocol.types import PrimaryClaim, Predicate, PrimaryInitProof, \
    PrimaryEqualInitProof, PrimaryPrecicateGEInitProof, PrimaryProof, \
    PrimaryEqualProof, PrimaryPredicateGEProof, \
    ID, ClaimInitDataType, ClaimAttributeValues
from anoncreds.protocol.utils import splitRevealedAttrs, fourSquares
from anoncreds.protocol.wallet.prover_wallet import ProverWallet
from config.config import cmod


class PrimaryClaimInitializer:
    def __init__(self, wallet: ProverWallet):
        self._wallet = wallet

    async def genClaimInitData(self, schemaId: ID) -> ClaimInitDataType:
        pk = await self._wallet.getPublicKey(schemaId)
        ms = await self._wallet.getMasterSecret(schemaId)
        vprime = cmod.randomBits(LARGE_VPRIME)
        N = pk.N
        Rms = pk.Rms
        S = pk.S
        U = (S ** vprime) * (Rms ** ms) % N

        return ClaimInitDataType(U=U, vPrime=vprime)

    async def preparePrimaryClaim(self, schemaId: ID, claim: PrimaryClaim):
        claimInitDat = await self._wallet.getPrimaryClaimInitData(schemaId)
        newV = claim.v + claimInitDat.vPrime
        claim = claim._replace(v=newV)
        return claim


class PrimaryProofBuilder:
    def __init__(self, wallet: ProverWallet):
        self._wallet = wallet

    async def initProof(self, schemaId, c1: PrimaryClaim,
                        revealedAttrs: Sequence[str],
                        predicates: Sequence[Predicate],
                        m1Tilde, m2Tilde, claimAttributes: Dict[str, ClaimAttributeValues]) -> PrimaryInitProof:
        if not c1:
            return None

        eqProof = await self._initEqProof(schemaId, c1, revealedAttrs,
                                          m1Tilde, m2Tilde, claimAttributes)
        geProofs = []
        for predicate in predicates:
            geProof = await self._initGeProof(schemaId, eqProof, c1,
                                              predicate, claimAttributes)
            geProofs.append(geProof)
        return PrimaryInitProof(eqProof, geProofs)

    async def finalizeProof(self, schemaId, cH,
                            initProof: PrimaryInitProof) -> PrimaryProof:
        if not initProof:
            return None

        cH = cmod.integer(cH)
        eqProof = await self._finalizeEqProof(schemaId, cH,
                                              initProof.eqProof)
        geProofs = []
        for initGeProof in initProof.geProofs:
            geProof = await self._finalizeGeProof(schemaId, cH, initGeProof,
                                                  eqProof)
            geProofs.append(geProof)
        return PrimaryProof(eqProof, geProofs)

    async def _initEqProof(self, schemaId, c1: PrimaryClaim,
                           revealedAttrs: Sequence[str], m1Tilde, m2Tilde, claimAttributes: Dict[str, ClaimAttributeValues]) \
            -> PrimaryEqualInitProof:
        m2Tilde = m2Tilde if m2Tilde else cmod.integer(
            cmod.randomBits(LARGE_MVECT))
        revealedAttrs, unrevealedAttrs = splitRevealedAttrs(claimAttributes, [a.name for a in revealedAttrs])
        mtilde = self._getMTilde(unrevealedAttrs)

        Ra = cmod.integer(cmod.randomBits(LARGE_VPRIME))
        pk = await self._wallet.getPublicKey(ID(schemaId=schemaId))

        A, e, v = c1.A, c1.e, c1.v
        Aprime = A * (pk.S ** Ra) % pk.N
        vprime = (v - e * Ra)
        eprime = e - (2 ** LARGE_E_START)

        etilde = cmod.integer(cmod.randomBits(LARGE_ETILDE))
        vtilde = cmod.integer(cmod.randomBits(LARGE_VTILDE))

        Rur = 1 % pk.N
        for k, value in unrevealedAttrs.items():
            if k in claimAttributes:
                Rur = Rur * (pk.R[k] ** mtilde[k])
        Rur *= pk.Rms ** m1Tilde
        Rur *= pk.Rctxt ** m2Tilde

        # T = ((Aprime ** etilde) * Rur * (pk.S ** vtilde)) % pk.N
        T = calcTeq(pk, Aprime, etilde, vtilde, mtilde, m1Tilde, m2Tilde,
                    unrevealedAttrs.keys())

        return PrimaryEqualInitProof(c1, Aprime, T, etilde, eprime, vtilde,
                                     vprime, mtilde, m1Tilde, m2Tilde,
                                     unrevealedAttrs.keys(), revealedAttrs)

    async def _initGeProof(self, schemaId, eqProof: PrimaryEqualInitProof,
                           c1: PrimaryClaim, predicate: Predicate, claimAttributes: Dict[str, ClaimAttributeValues]) \
            -> PrimaryPrecicateGEInitProof:
        # gen U for Delta
        pk = await self._wallet.getPublicKey(ID(schemaId=schemaId))
        k, value = predicate.attrName, predicate.value
        delta = claimAttributes[k].encoded - value
        if delta < 0:
            raise ValueError("Predicate is not satisfied")

        u = fourSquares(delta)

        # prepare C list
        r = {}
        T = {}
        CList = []
        for i in range(0, ITERATIONS):
            r[str(i)] = cmod.integer(cmod.randomBits(LARGE_VPRIME))
            T[str(i)] = (pk.Z ** u[str(i)]) * (pk.S ** r[str(i)]) % pk.N
            CList.append(T[str(i)])
        r[DELTA] = cmod.integer(cmod.randomBits(LARGE_VPRIME))
        T[DELTA] = (pk.Z ** delta) * (pk.S ** r[DELTA]) % pk.N
        CList.append(T[DELTA])

        # prepare Tau List
        utilde = {}
        rtilde = {}
        for i in range(0, ITERATIONS):
            utilde[str(i)] = cmod.integer(cmod.randomBits(LARGE_UTILDE))
            rtilde[str(i)] = cmod.integer(cmod.randomBits(LARGE_RTILDE))
        rtilde[DELTA] = cmod.integer(cmod.randomBits(LARGE_RTILDE))
        alphatilde = cmod.integer(cmod.randomBits(LARGE_ALPHATILDE))

        TauList = calcTge(pk, utilde, rtilde, eqProof.mTilde[k], alphatilde, T)
        return PrimaryPrecicateGEInitProof(CList, TauList, u, utilde, r, rtilde,
                                           alphatilde, predicate, T)

    async def _finalizeEqProof(self, schemaId, cH,
                               initProof: PrimaryEqualInitProof) -> PrimaryEqualProof:
        e = initProof.eTilde + (cH * initProof.ePrime)
        v = initProof.vTilde + (cH * initProof.vPrime)

        m = {}

        claimAttributes = await self._wallet.getClaimAttributes(ID(schemaId=schemaId))

        for k in initProof.unrevealedAttrs:
            m[str(k)] = initProof.mTilde[str(k)] + (
                cH * claimAttributes[str(k)].encoded)
        ms = await self._wallet.getMasterSecret(ID(schemaId=schemaId))
        m1 = initProof.m1Tilde + (cH * ms)
        m2 = initProof.m2Tilde + (cH * initProof.c1.m2)

        return PrimaryEqualProof(e, v, m, m1, m2, initProof.Aprime,
                                 initProof.revealedAttrs)

    async def _finalizeGeProof(self, schemaId, cH,
                               initProof: PrimaryPrecicateGEInitProof,
                               eqProof: PrimaryEqualProof) \
            -> PrimaryPredicateGEProof:
        u = {}
        r = {}
        urproduct = 0
        for i in range(0, ITERATIONS):
            u[str(i)] = initProof.uTilde[str(i)] + cH * initProof.u[str(i)]
            r[str(i)] = initProof.rTilde[str(i)] + cH * initProof.r[str(i)]
            urproduct += initProof.u[str(i)] * initProof.r[str(i)]
            r[DELTA] = initProof.rTilde[DELTA] + cH * initProof.r[DELTA]

        alpha = initProof.alphaTilde + cH * (initProof.r[DELTA] - urproduct)

        k, value = initProof.predicate.attrName, initProof.predicate.value
        return PrimaryPredicateGEProof(u, r, alpha, eqProof.m[str(k)],
                                       initProof.T, initProof.predicate)

    def _getMTilde(self, unrevealedAttrs):
        mtilde = {}
        for key, value in unrevealedAttrs.items():
            mtilde[key] = cmod.integer(cmod.randomBits(LARGE_MVECT))
        return mtilde
