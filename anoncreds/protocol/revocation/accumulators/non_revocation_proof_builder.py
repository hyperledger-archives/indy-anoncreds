from typing import Dict

from anoncreds.protocol.revocation.accumulators.non_revocation_common import createTauListValues, \
    createTauListExpectedValues
from anoncreds.protocol.types import NonRevocationClaim, PublicData, NonRevocInitProof, \
    NonRevocProofXList, NonRevocProofCList, NonRevocProof, \
    T, CredentialDefinition, PublicDataRevocation
from anoncreds.protocol.utils import bytes_to_ZR
from config.config import cmod


class NonRevocationClaimInitializer:
    def __init__(self, publicData: Dict[CredentialDefinition, PublicDataRevocation], m1, m2: Dict[str, T]):
        self._groups = {x: cmod.PairingGroup(y.pkR.groupType) for x, y in publicData.items()}
        self._data = publicData
        self._m1 = int(m1)
        self._m2 = {x: int(y) for x, y in m2.items()}
        self._genPresentationData()

    def _genPresentationData(self):
        self._vrPrime = {}
        self._Ur = {}
        for credDef, val in self._data.items():
            vrPrime = self._groups[credDef].random(cmod.ZR)
            self._vrPrime[credDef] = vrPrime
            self._Ur[credDef] = (val.pkR.h2 ** vrPrime)

    def getUr(self, credDef):
        return self._Ur[credDef]

    def initNonRevocationClaim(self, credDef, claim: NonRevocationClaim):
        newV = claim.v + self._vrPrime[credDef]
        claim = claim._replace(v = newV)
        self._testWitnessCredential(credDef, claim)
        return claim

    def _testWitnessCredential(self, credDef, claim: NonRevocationClaim):
        pk = self._data[credDef].pkR
        acc = self._data[credDef].accum
        accPk = self._data[credDef].pkAccum
        m2 = self._m2[credDef]

        zCalc = cmod.pair(claim.gi, acc.acc) / cmod.pair(pk.g, claim.witness.omega)
        if zCalc != accPk.z:
            raise ValueError("issuer is sending incorrect data")

        pairGGCalc = cmod.pair(pk.pk * claim.gi, claim.witness.sigmai)
        pairGG = cmod.pair(pk.g, pk.g)
        if pairGGCalc != pairGG:
            raise ValueError("issuer is sending incorrect data")

        pairH1 = cmod.pair(claim.sigma, pk.y * (pk.h ** claim.c))
        pairH2 = cmod.pair(pk.h0 * (pk.h1 ** m2) * (pk.h2 ** claim.v) * claim.gi, pk.h)
        if pairH1 != pairH2:
            raise ValueError("issuer is sending incorrect data")

        return True


class NonRevocationProofBuilder:
    def __init__(self, publicData: PublicDataRevocation):
        self._groups = {x: cmod.PairingGroup(y.pkR.groupType) for x, y in publicData.items()}
        self._data = publicData

    def updateNonRevocationClaim(self, credDef, c2: NonRevocationClaim):
        oldV = c2.witness.V
        newV = self._data[credDef].accum.V
        newAccum = self._data[credDef].accum
        g = self._data[credDef].g

        if c2.i not in newV:
            raise ValueError("Can not update Witness. I'm revoced.")

        if oldV != newV:
            vOldMinusNew = oldV - newV
            vNewMinusOld = newV - oldV
            omegaDenom = 1
            for j in vOldMinusNew:
                omegaDenom *= g[newAccum.L + 1 - j + c2.i]
            omegaNum = 1
            newOmega = c2.witness.omega
            for j in vNewMinusOld:
                omegaNum *= g[newAccum.L + 1 - j + c2.i]
                newOmega *= omegaNum / omegaDenom

            newWitness = c2.witness._replace(V=newV, omega=newOmega)
            c2 = c2._replace(witness=newWitness)

        return c2

    def initProof(self, credDef, c2: NonRevocationClaim) -> NonRevocInitProof:
        if not c2:
            return None

        pkR = self._data[credDef].pkR
        accum = self._data[credDef].accum
        CList = []
        TauList = []

        cListParams = self._genCListParams(credDef, c2)
        proofCList = self._createCListValues(credDef, c2, cListParams)
        CList.extend(proofCList.asList())

        tauListParams = self._genTauListParams(credDef)
        proofTauList = createTauListValues(pkR, accum, tauListParams, proofCList)
        TauList.extend(proofTauList.asList())

        return NonRevocInitProof(proofCList, proofTauList, cListParams, tauListParams)

    def finalizeProof(self, credDef, cH, initProof: NonRevocInitProof) -> NonRevocProof:
        if not initProof:
            return None

        chNum_z = bytes_to_ZR(cH, self._groups[credDef])
        XList = NonRevocProofXList()
        XList.fromList(
            [x - chNum_z * y for x, y in zip(initProof.TauListParams.asList(), initProof.CListParams.asList())])
        return NonRevocProof(XList, initProof.CList)

    def _genCListParams(self, credDef, c2: NonRevocationClaim) -> NonRevocProofXList:
        group = self._groups[credDef]
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
        return NonRevocProofXList(rho=rho, r=r, rPrime=rPrime, rPrimePrime=rPrimePrime,
                                  rPrimePrimePrime=rPrimePrimePrime,
                                  o=o, oPrime=oPrime, m=m, mPrime=mPrime, t=t, tPrime=tPrime, m2=m2, s=c2.v, c=c2.c)

    def _createCListValues(self, credDef, c2: NonRevocationClaim,
                           params: NonRevocProofXList) -> NonRevocProofCList:
        pk = self._data[credDef].pkR
        E = (pk.h ** params.rho) * (pk.htilde ** params.o)
        D = (pk.g ** params.r) * (pk.htilde ** params.oPrime)
        A = c2.sigma * (pk.htilde ** params.rho)
        G = c2.gi * (pk.htilde ** params.r)
        W = c2.witness.omega * (pk.htilde ** params.rPrime)
        S = c2.witness.sigmai * (pk.htilde ** params.rPrimePrime)
        U = c2.witness.ui * (pk.htilde ** params.rPrimePrimePrime)
        return NonRevocProofCList(E, D, A, G, W, S, U)

    def _genTauListParams(self, credDef) -> NonRevocProofXList:
        return NonRevocProofXList(group=self._groups[credDef])

    def testProof(self, credDef, c2: NonRevocationClaim):
        pkR = self._data[credDef].pkR
        accum = self._data[credDef].accum
        accumPk = self._data[credDef].pkAccum

        cListParams = self._genCListParams(credDef, c2)
        proofCList = self._createCListValues(credDef, c2, cListParams)
        proofTauList = createTauListValues(pkR, accum, cListParams, proofCList)

        proofTauListCalc = createTauListExpectedValues(pkR, accum, accumPk, proofCList)

        if proofTauListCalc.asList() != proofTauList.asList():
            raise ValueError("revocation proof is incorrect")

        return True
