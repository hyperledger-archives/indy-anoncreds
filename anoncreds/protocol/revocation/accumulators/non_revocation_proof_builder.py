from anoncreds.protocol.globals import PAIRING_GROUP
from anoncreds.protocol.revocation.accumulators.non_revocation_common import \
    createTauListValues, \
    createTauListExpectedValues
from anoncreds.protocol.types import NonRevocationClaim, NonRevocInitProof, \
    NonRevocProofXList, NonRevocProofCList, NonRevocProof, \
    ID, ClaimInitDataType
from anoncreds.protocol.utils import int_to_ZR
from anoncreds.protocol.wallet.prover_wallet import ProverWallet
from config.config import cmod


class NonRevocationClaimInitializer:
    def __init__(self, wallet: ProverWallet):
        self._wallet = wallet

    async def genClaimInitData(self, schemaId: ID) -> ClaimInitDataType:
        group = cmod.PairingGroup(
            PAIRING_GROUP)  # super singular curve, 1024 bits
        pkR = await self._wallet.getPublicKeyRevocation(schemaId)

        vrPrime = group.random(cmod.ZR)
        Ur = (pkR.h2 ** vrPrime)

        return ClaimInitDataType(U=Ur, vPrime=vrPrime)

    async def initNonRevocationClaim(self, schemaId: ID,
                                     claim: NonRevocationClaim):
        vrPrime = (
        await self._wallet.getNonRevocClaimInitData(schemaId)).vPrime
        newV = claim.v + vrPrime
        claim = claim._replace(v=newV)
        await self._testWitnessCredential(schemaId, claim)
        return claim

    async def _testWitnessCredential(self, schemaid: ID,
                                     claim: NonRevocationClaim):
        pkR = await self._wallet.getPublicKeyRevocation(schemaid)
        acc = await self._wallet.getAccumulator(schemaid)
        accPk = await self._wallet.getPublicKeyAccumulator(schemaid)
        m2 = int(await self._wallet.getContextAttr(schemaid))

        zCalc = cmod.pair(claim.witness.gi, acc.acc) / cmod.pair(pkR.g,
                                                         claim.witness.omega)
        if zCalc != accPk.z:
            raise ValueError("issuer is sending incorrect data")

        pairGGCalc = cmod.pair(pkR.pk * claim.witness.gi, claim.witness.sigmai)
        pairGG = cmod.pair(pkR.g, pkR.gprime)
        if pairGGCalc != pairGG:
            raise ValueError("issuer is sending incorrect data")

        pairH1 = cmod.pair(claim.sigma, pkR.y * (pkR.hhat ** claim.c))
        pairH2 = cmod.pair(
            pkR.h0 * (pkR.h1 ** m2) * (pkR.h2 ** claim.v) * claim.witness.gi, pkR.hhat)
        if pairH1 != pairH2:
            raise ValueError("issuer is sending incorrect data")

        return True


class NonRevocationProofBuilder:
    def __init__(self, wallet: ProverWallet):
        self._wallet = wallet

    async def updateNonRevocationClaim(self, schemaId,
                                       c2: NonRevocationClaim, ts=None,
                                       seqNo=None):
        if await self._wallet.shouldUpdateAccumulator(
                schemaId=ID(schemaId=schemaId), ts=ts,
                seqNo=seqNo):
            await self._wallet.updateAccumulator(schemaId=ID(schemaId=schemaId),
                                                 ts=ts,
                                                 seqNo=seqNo)

        oldV = c2.witness.V
        newAccum = await self._wallet.getAccumulator(
            ID(schemaId=schemaId))
        newV = newAccum.V
        tails = await self._wallet.getTails(ID(schemaId=schemaId))

        if c2.i not in newV:
            raise ValueError("Can not update Witness. I'm revoced.")

        if oldV != newV:
            vOldMinusNew = oldV - newV
            vNewMinusOld = newV - oldV
            omegaDenom = 1
            for j in vOldMinusNew:
                omegaDenom *= tails.gprime[newAccum.L + 1 - j + c2.i]
            omegaNum = 1
            newOmega = c2.witness.omega
            for j in vNewMinusOld:
                omegaNum *= tails.gprime[newAccum.L + 1 - j + c2.i]
                newOmega *= omegaNum / omegaDenom

            newWitness = c2.witness._replace(V=newV, omega=newOmega)
            c2 = c2._replace(witness=newWitness)

            await self._wallet.submitNonRevocClaim(schemaId=ID(schemaId=schemaId),
                                                   claim=c2)

        return c2

    async def initProof(self, schemaId,
                        c2: NonRevocationClaim) -> NonRevocInitProof:
        if not c2:
            return None

        c2 = await self.updateNonRevocationClaim(schemaId, c2)

        pkR = await self._wallet.getPublicKeyRevocation(ID(schemaId=schemaId))
        accum = await self._wallet.getAccumulator(ID(schemaId=schemaId))
        CList = []
        TauList = []

        cListParams = self._genCListParams(schemaId, c2)
        proofCList = self._createCListValues(schemaId, c2, cListParams, pkR)
        CList.extend(proofCList.asList())

        tauListParams = self._genTauListParams(schemaId)
        proofTauList = createTauListValues(pkR, accum, tauListParams,
                                           proofCList)
        TauList.extend(proofTauList.asList())

        return NonRevocInitProof(proofCList, proofTauList, cListParams,
                                 tauListParams)

    async def finalizeProof(self, schemaId, cH,
                            initProof: NonRevocInitProof) -> NonRevocProof:
        if not initProof:
            return None

        group = cmod.PairingGroup(
            PAIRING_GROUP)  # super singular curve, 1024 bits
        chNum_z = int_to_ZR(cH, group)
        XList = NonRevocProofXList.fromList(
            [x - chNum_z * y for x, y in zip(initProof.TauListParams.asList(),
                                             initProof.CListParams.asList())]
        )
        return NonRevocProof(XList, initProof.CList)

    def _genCListParams(self, schemaId,
                        c2: NonRevocationClaim) -> NonRevocProofXList:
        group = cmod.PairingGroup(
            PAIRING_GROUP)  # super singular curve, 1024 bits
        rho = group.random(cmod.ZR)
        r = group.random(cmod.ZR)
        rPrime = group.random(cmod.ZR)
        rPrimePrime = group.random(cmod.ZR)
        rPrimePrimePrime = group.random(cmod.ZR)
        o = group.random(cmod.ZR)
        oPrime = group.random(cmod.ZR)
        m = rho * c2.c
        mPrime = r * rPrimePrime
        t = o * c2.c
        tPrime = oPrime * rPrimePrime
        m2 = group.init(cmod.ZR, int(c2.m2))
        return NonRevocProofXList(rho=rho, r=r, rPrime=rPrime,
                                  rPrimePrime=rPrimePrime,
                                  rPrimePrimePrime=rPrimePrimePrime,
                                  o=o, oPrime=oPrime, m=m, mPrime=mPrime, t=t,
                                  tPrime=tPrime, m2=m2, s=c2.v, c=c2.c)

    def _createCListValues(self, schemaId, c2: NonRevocationClaim,
                           params: NonRevocProofXList,
                           pkR) -> NonRevocProofCList:
        E = (pkR.h ** params.rho) * (pkR.htilde ** params.o)
        D = (pkR.g ** params.r) * (pkR.htilde ** params.oPrime)
        A = c2.sigma * (pkR.htilde ** params.rho)
        G = c2.witness.gi * (pkR.htilde ** params.r)
        W = c2.witness.omega * (pkR.hhat ** params.rPrime)
        S = c2.witness.sigmai * (pkR.hhat ** params.rPrimePrime)
        U = c2.witness.ui * (pkR.hhat ** params.rPrimePrimePrime)
        return NonRevocProofCList(E, D, A, G, W, S, U)

    def _genTauListParams(self, schemaId) -> NonRevocProofXList:
        group = cmod.PairingGroup(
            PAIRING_GROUP)  # super singular curve, 1024 bits
        return NonRevocProofXList(group=group)

    async def testProof(self, schemaId, c2: NonRevocationClaim):
        pkR = await self._wallet.getPublicKeyRevocation(ID(schemaId=schemaId))
        accum = await self._wallet.getAccumulator(ID(schemaId=schemaId))
        accumPk = await self._wallet.getPublicKeyAccumulator(
            ID(schemaId=schemaId))

        cListParams = self._genCListParams(schemaId, c2)
        proofCList = self._createCListValues(schemaId, c2, cListParams, pkR)
        proofTauList = createTauListValues(pkR, accum, cListParams, proofCList)

        proofTauListCalc = createTauListExpectedValues(pkR, accum, accumPk,
                                                       proofCList)

        if proofTauListCalc.asList() != proofTauList.asList():
            raise ValueError("revocation proof is incorrect")

        return True
