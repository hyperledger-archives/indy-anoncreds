from functools import reduce

from charm.toolbox.pairinggroup import PairingGroup, ZR, pair

from anoncreds.protocol.revocation.accumulators.types import RevocationPublicKey, Accumulator, WitnessCredential, GType, \
    RevocationProof, ProofParams, ProofCList, ProofTauList
from anoncreds.protocol.utils import get_hash_hex, hex_hash_to_ZR


# TODO: it works for one issuer only now
class ProofRevocationBuilder:
    def __init__(self, issuerId, revocPK: RevocationPublicKey, ms):
        self._issuerId = issuerId
        self._group = PairingGroup(revocPK.groupType)
        self._pk = revocPK
        self._ms = int(ms)

        self._vrPrime = self._group.random(ZR)
        self._vrPrime = self._group.random(ZR)
        self._Ur = (self._pk.h1 ** self._ms) * (self._pk.h2 ** self._vrPrime)

    @property
    def Ur(self):
        return self._Ur

    def prepareProofNonVerification(self, witnessCred: WitnessCredential,
                                    accum: Accumulator, g: GType, nonce) -> RevocationProof:
        # update vPrime parameter for Witness
        witnessCred = self._getPresentationWitnessCredential(witnessCred)

        # update V and omega in witness to correspond to the new accumulator
        witnessCred = self._updateWitness(witnessCred, accum, g)

        # check whether issued witness is correct
        self._testWitnessCredential(witnessCred, accum)

        # prepare non-revocation proof
        return self._prepareProof(witnessCred, accum, nonce)

    def _getPresentationWitnessCredential(self, W: WitnessCredential):
        W.v += self._vrPrime
        return W

    def _updateWitness(self, witnessCred: WitnessCredential, newAccum: Accumulator, g: GType):
        oldV = witnessCred.witi.V
        newV = newAccum.V

        if witnessCred.i not in newV:
            raise ValueError("Can not update Witness. I'm revoced.")

        if oldV != newV:
            witnessCred.witi.V = newV

            vOldMinusNew = oldV - newV
            vNewMinusOld = newV - oldV
            omegaDenom = 1
            for j in vOldMinusNew:
                omegaDenom *= g[newAccum.L + 1 - j + witnessCred.i]
            omegaNum = 1
            for j in vNewMinusOld:
                omegaNum *= g[newAccum.L + 1 - j + witnessCred.i]

                witnessCred.witi.omega = witnessCred.witi.omega * omegaNum / omegaDenom

        return witnessCred

    def _testWitnessCredential(self, W: WitnessCredential, acc: Accumulator):
        zCalc = pair(W.gi, acc.acc) / pair(self._pk.g, W.witi.omega)
        if zCalc != acc.pk.z:
            raise ValueError("issuer is sending incorrect data")

        pairGGCalc = pair(self._pk.pk * W.gi, W.witi.sigmai)
        pairGG = pair(self._pk.g, self._pk.g)
        if pairGGCalc != pairGG:
            raise ValueError("issuer is sending incorrect data")

        pairH1 = pair(W.sigma, self._pk.y * (self._pk.h ** W.c))
        pairH2 = pair(self._pk.h0 * (self._pk.h1 ** self._ms) * (self._pk.h2 ** W.v) * W.gi, self._pk.h)
        if pairH1 != pairH2:
            raise ValueError("issuer is sending incorrect data")

        return True

    def _prepareProof(self, witnessCred: WitnessCredential,
                      accum: Accumulator, nonce) -> RevocationProof:
        CList = []
        TauList = []
        XList = ProofParams()

        cListParams = self._genCListParams(self._group, witnessCred)
        proofCList = self._createCListValues(self._pk, witnessCred, cListParams)
        CList.extend(proofCList.asList())

        tauListParams = self._genTauListParams(self._group)
        proofTauList = self.createTauListValues(self._pk, accum, tauListParams, proofCList)
        TauList.extend(proofTauList.asList())

        cH = get_hash_hex(nonce, *reduce(lambda x, y: x + y, [TauList, CList]), group=self._group)
        chNum_z = hex_hash_to_ZR(cH, self._group)

        XList.fromList([x - chNum_z * y for x, y in zip(tauListParams.asList(), cListParams.asList())])

        return RevocationProof(cH, XList, proofCList)

    def _genCListParams(self, group, w: WitnessCredential) -> ProofParams:
        rho = group.random(ZR)
        r = group.random(ZR)
        rPrime = group.random(ZR)
        rPrimePrime = group.random(ZR)
        rPrimePrimePrime = group.random(ZR)
        o = group.random(ZR)
        oPrime = group.random(ZR)
        m = rho * w.c
        mPrime = r * rPrimePrime
        t = o * w.c
        tPrime = oPrime * rPrimePrime
        mR = group.init(ZR, self._ms)
        return ProofParams(rho=rho, r=r, rPrime=rPrime, rPrimePrime=rPrimePrime, rPrimePrimePrime=rPrimePrimePrime,
                           o=o, oPrime=oPrime, m=m, mPrime=mPrime, t=t, tPrime=tPrime, mR=mR, s=w.v, c=w.c)

    def _createCListValues(self, pk: RevocationPublicKey, w: WitnessCredential, params: ProofParams) -> ProofCList:
        E = (pk.h ** params.rho) * (pk.htilde ** params.o)
        D = (pk.g ** params.r) * (pk.htilde ** params.oPrime)
        A = w.sigma * (pk.htilde ** params.rho)
        G = w.gi * (pk.htilde ** params.r)
        W = w.witi.omega * (pk.htilde ** params.rPrime)
        S = w.witi.sigmai * (pk.htilde ** params.rPrimePrime)
        U = w.witi.ui * (pk.htilde ** params.rPrimePrimePrime)
        return ProofCList(E, D, A, G, W, S, U)

    def _genTauListParams(self, group) -> ProofParams:
        return ProofParams(group=group)

    @staticmethod
    def createTauListValues(pk: RevocationPublicKey, accum: Accumulator, params: ProofParams,
                            proofC: ProofCList) -> ProofTauList:
        T1 = (pk.h ** params.rho) * (pk.htilde ** params.o)
        T2 = (proofC.E ** params.c) * (pk.h ** (-params.m)) * (pk.htilde ** (-params.t))
        T3 = ((pair(proofC.A, pk.h) ** params.c) *
              (pair(pk.htilde, pk.h) ** params.r)) / \
             ((pair(pk.htilde, pk.y) ** params.rho) *
              (pair(pk.htilde, pk.h) ** params.m) *
              (pair(pk.h1, pk.h) ** params.mR) *
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
        return ProofTauList(T1, T2, T3, T4, T5, T6, T7, T8)

    @staticmethod
    def createTauListExpectedValues(pk: RevocationPublicKey, accum: Accumulator,
                                    proofC: ProofCList) -> ProofTauList:
        T1 = proofC.E
        T2 = pk.h / pk.h
        T3 = pair(pk.h0 * proofC.G, pk.h) / pair(proofC.A, pk.y)
        T4 = pair(proofC.G, accum.acc) / (pair(pk.g, proofC.W) * accum.pk.z)
        T5 = proofC.D
        T6 = pk.h / pk.h
        T7 = pair(pk.pk * proofC.G, proofC.S) / pair(pk.g, pk.g)
        T8 = pair(proofC.G, pk.u) / pair(pk.g, proofC.U)
        return ProofTauList(T1, T2, T3, T4, T5, T6, T7, T8)

    def testProof(self, witnessCred: WitnessCredential, accum: Accumulator):
        cListParams = self._genCListParams(self._group, witnessCred)
        proofCList = self._createCListValues(self._pk, witnessCred, cListParams)
        proofTauList = self.createTauListValues(self._pk, accum, cListParams, proofCList)

        proofTauListCalc = ProofRevocationBuilder.createTauListExpectedValues(self._pk, accum, proofCList)

        if proofTauListCalc.asList() != proofTauList.asList():
            raise ValueError("revocation proof is incorrect")

        return True
