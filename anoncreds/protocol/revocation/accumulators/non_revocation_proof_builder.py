from typing import Dict

from charm.toolbox.pairinggroup import PairingGroup, ZR, pair

from anoncreds.protocol.types import NonRevocationClaim, PublicData, Accumulator, NonRevocInitProof, \
    NonRevocProofXList, NonRevocProofCList, RevocationPublicKey, NonRevocProofTauList, NonRevocProof, \
    AccumulatorPublicKey, T
from anoncreds.protocol.utils import bytes_to_ZR


class NonRevocationClaimInitializer:
    def __init__(self, publicData: Dict[str, PublicData], m1, m2: Dict[str, T]):
        self._groups = {x: PairingGroup(y.pkR.groupType) for x, y in publicData.items()}
        self._data = publicData
        self._m1 = int(m1)
        self._m2 = {x: int(y) for x, y in m2.items()}
        self._genPresentationData()

    def _genPresentationData(self):
        self._vrPrime = {}
        self._Ur = {}
        for issuerId, val in self._data.items():
            vrPrime = self._groups[issuerId].random(ZR)
            self._vrPrime[issuerId] = vrPrime
            self._Ur[issuerId] = (val.pkR.h2 ** vrPrime)

    def getUr(self, issuerId):
        return self._Ur[issuerId]

    def initNonRevocationClaim(self, issuerId, claim: NonRevocationClaim):
        claim.v += self._vrPrime[issuerId]
        self._testWitnessCredential(issuerId, claim)
        return claim

    def _testWitnessCredential(self, issuerId, claim: NonRevocationClaim):
        pk = self._data[issuerId].pkR
        acc = self._data[issuerId].accum
        accPk = self._data[issuerId].pkAccum
        m2 = self._m2[issuerId]

        zCalc = pair(claim.gi, acc.acc) / pair(pk.g, claim.witness.omega)
        if zCalc != accPk.z:
            raise ValueError("issuer is sending incorrect data")

        pairGGCalc = pair(pk.pk * claim.gi, claim.witness.sigmai)
        pairGG = pair(pk.g, pk.g)
        if pairGGCalc != pairGG:
            raise ValueError("issuer is sending incorrect data")

        pairH1 = pair(claim.sigma, pk.y * (pk.h ** claim.c))
        pairH2 = pair(pk.h0 * (pk.h1 ** m2) * (pk.h2 ** claim.v) * claim.gi, pk.h)
        if pairH1 != pairH2:
            raise ValueError("issuer is sending incorrect data")

        return True


class NonRevocationProofBuilder:
    def __init__(self, publicData: PublicData):
        self._groups = {x: PairingGroup(y.pkR.groupType) for x, y in publicData.items()}
        self._data = publicData

    def updateNonRevocationClaim(self, issuerId, c2: NonRevocationClaim):
        oldV = c2.witness.V
        newV = self._data[issuerId].accum.V
        newAccum = self._data[issuerId].accum
        g = self._data[issuerId].g

        if c2.i not in newV:
            raise ValueError("Can not update Witness. I'm revoced.")

        if oldV != newV:
            c2.witness.V = newV

            vOldMinusNew = oldV - newV
            vNewMinusOld = newV - oldV
            omegaDenom = 1
            for j in vOldMinusNew:
                omegaDenom *= g[newAccum.L + 1 - j + c2.i]
            omegaNum = 1
            for j in vNewMinusOld:
                omegaNum *= g[newAccum.L + 1 - j + c2.i]

                c2.witness.omega = c2.witness.omega * omegaNum / omegaDenom

        return c2

    def initProof(self, issuerId, c2: NonRevocationClaim) -> NonRevocInitProof:
        if not c2:
            return None

        CList = []
        TauList = []

        cListParams = self._genCListParams(self._groups[issuerId], c2)
        proofCList = self._createCListValues(self._data[issuerId].pkR, c2, cListParams)
        CList.extend(proofCList.asList())

        tauListParams = self._genTauListParams(self._groups[issuerId])
        proofTauList = self.createTauListValues(self._data[issuerId].pkR, self._data[issuerId].accum, tauListParams,
                                                proofCList)
        TauList.extend(proofTauList.asList())

        return NonRevocInitProof(proofCList, proofTauList, cListParams, tauListParams)

    def finalizeProof(self, issuerId, cH, initProof: NonRevocInitProof) -> NonRevocProof:
        if not initProof:
            return None

        chNum_z = bytes_to_ZR(cH, self._groups[issuerId])
        XList = NonRevocProofXList()
        XList.fromList(
            [x - chNum_z * y for x, y in zip(initProof.TauListParams.asList(), initProof.CListParams.asList())])
        return NonRevocProof(XList, initProof.CList)

    def _genCListParams(self, group, c2: NonRevocationClaim) -> NonRevocProofXList:
        rho = group.random(ZR)
        r = group.random(ZR)
        rPrime = group.random(ZR)
        rPrimePrime = group.random(ZR)
        rPrimePrimePrime = group.random(ZR)
        o = group.random(ZR)
        oPrime = group.random(ZR)
        m = rho * c2.c
        mPrime = r * rPrimePrime
        t = o * c2.c
        tPrime = oPrime * rPrimePrime
        m2 = group.init(ZR, int(c2.m2))
        return NonRevocProofXList(rho=rho, r=r, rPrime=rPrime, rPrimePrime=rPrimePrime,
                                  rPrimePrimePrime=rPrimePrimePrime,
                                  o=o, oPrime=oPrime, m=m, mPrime=mPrime, t=t, tPrime=tPrime, m2=m2, s=c2.v, c=c2.c)

    def _createCListValues(self, pk: RevocationPublicKey, c2: NonRevocationClaim,
                           params: NonRevocProofXList) -> NonRevocProofCList:
        E = (pk.h ** params.rho) * (pk.htilde ** params.o)
        D = (pk.g ** params.r) * (pk.htilde ** params.oPrime)
        A = c2.sigma * (pk.htilde ** params.rho)
        G = c2.gi * (pk.htilde ** params.r)
        W = c2.witness.omega * (pk.htilde ** params.rPrime)
        S = c2.witness.sigmai * (pk.htilde ** params.rPrimePrime)
        U = c2.witness.ui * (pk.htilde ** params.rPrimePrimePrime)
        return NonRevocProofCList(E, D, A, G, W, S, U)

    def _genTauListParams(self, group) -> NonRevocProofXList:
        return NonRevocProofXList(group=group)

    @staticmethod
    def createTauListValues(pk: RevocationPublicKey, accum: Accumulator, params: NonRevocProofXList,
                            proofC: NonRevocProofCList) -> NonRevocProofTauList:
        T1 = (pk.h ** params.rho) * (pk.htilde ** params.o)
        T2 = (proofC.E ** params.c) * (pk.h ** (-params.m)) * (pk.htilde ** (-params.t))
        T3 = ((pair(proofC.A, pk.h) ** params.c) *
              (pair(pk.htilde, pk.h) ** params.r)) / \
             ((pair(pk.htilde, pk.y) ** params.rho) *
              (pair(pk.htilde, pk.h) ** params.m) *
              (pair(pk.h1, pk.h) ** params.m2) *
              (pair(pk.h2, pk.h) ** params.s))
        T4 = (pair(pk.htilde, accum.acc) ** params.r) * \
             (pair(1 / pk.g, pk.htilde) ** params.rPrime)
        T5 = (pk.g ** params.r) * (pk.htilde ** params.oPrime)
        T6 = (proofC.D ** params.rPrimePrime) * (pk.g ** -params.mPrime) * (pk.htilde ** -params.tPrime)
        T7 = (pair(pk.pk * proofC.G, pk.htilde) ** params.rPrimePrime) * \
             (pair(pk.htilde, pk.htilde) ** -params.mPrime) * \
             (pair(pk.htilde, proofC.S) ** params.r)
        T8 = (pair(pk.htilde, pk.u) ** params.r) * \
             (pair(1 / pk.g, pk.htilde) ** params.rPrimePrimePrime)
        return NonRevocProofTauList(T1, T2, T3, T4, T5, T6, T7, T8)

    @staticmethod
    def createTauListExpectedValues(pk: RevocationPublicKey, accum: Accumulator, accumPk: AccumulatorPublicKey,
                                    proofC: NonRevocProofCList) -> NonRevocProofTauList:
        T1 = proofC.E
        T2 = pk.h / pk.h
        T3 = pair(pk.h0 * proofC.G, pk.h) / pair(proofC.A, pk.y)
        T4 = pair(proofC.G, accum.acc) / (pair(pk.g, proofC.W) * accumPk.z)
        T5 = proofC.D
        T6 = pk.h / pk.h
        T7 = pair(pk.pk * proofC.G, proofC.S) / pair(pk.g, pk.g)
        T8 = pair(proofC.G, pk.u) / pair(pk.g, proofC.U)
        return NonRevocProofTauList(T1, T2, T3, T4, T5, T6, T7, T8)

    def testProof(self, issuerId, c2: NonRevocationClaim):
        cListParams = self._genCListParams(self._groups[issuerId], c2)
        proofCList = self._createCListValues(self._data[issuerId].pkR, c2, cListParams)
        proofTauList = self.createTauListValues(self._data[issuerId].pkR, self._data[issuerId].accum, cListParams,
                                                proofCList)

        proofTauListCalc = NonRevocationProofBuilder.createTauListExpectedValues(
            self._data[issuerId].pkR, self._data[issuerId].accum, self._data[issuerId].pkAccum, proofCList)

        if proofTauListCalc.asList() != proofTauList.asList():
            raise ValueError("revocation proof is incorrect")

        return True
