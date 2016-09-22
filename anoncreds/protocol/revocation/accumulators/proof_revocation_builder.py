from functools import reduce
from typing import Dict

from charm.toolbox.pairinggroup import PairingGroup, ZR, pair

from anoncreds.protocol.revocation.accumulators.types import RevocationPublicKey, Accumulator, WitnessCredential, GType, \
    RevocationProof, ProofParams, ProofCList, ProofTauList
from anoncreds.protocol.utils import get_hash_hex, hex_hash_to_ZR


class ProofRevocationBuilder:
    def __init__(self, groups: Dict[str, PairingGroup], revocationPks: Dict[str, RevocationPublicKey], ms):
        self._groups = groups
        self._revocationPks = revocationPks
        self._ms = int(ms)

        self._vrPrime = {}
        for key, val in revocationPks.items():
            self._vrPrime[key] = self._groups[key].random(ZR)

        self._Ur = {}
        for key, val in revocationPks.items():
            self._Ur[key] = (val.h1 ** self._ms) * (val.h2 ** self._vrPrime[key])

    @property
    def Ur(self):
        return self._Ur

    def testWitnessCredentials(self, Ws: Dict[str, WitnessCredential], accs: Dict[str, Accumulator]):
        result = True
        for key, val in Ws.items():
            result &= self.testWitnessCredential(key, val, accs[key])
        return result

    def testWitnessCredential(self, issuerId, W: WitnessCredential, acc: Accumulator):
        W = self.getPresentationWitnessCredential(issuerId, W)

        pk = self._revocationPks[issuerId]
        zCalc = pair(W.gi, acc.acc) / pair(pk.g, W.witi.omega)
        if zCalc != acc.pk.z:
            raise ValueError("issuer is sending incorrect data")

        pairGGCalc = pair(pk.pk * W.gi, W.witi.sigmai)
        pairGG = pair(pk.g, pk.g)
        if pairGGCalc != pairGG:
            raise ValueError("issuer is sending incorrect data")

        pairH1 = pair(W.sigma, pk.y * (pk.h ** W.c))
        pairH2 = pair(pk.h0 * (pk.h1 ** self._ms) * (pk.h2 ** W.v) * W.gi, pk.h)
        if pairH1 != pairH2:
            raise ValueError("issuer is sending incorrect data")

        return True

    def getPresentationWitnessCredential(self, issuerId, W: WitnessCredential):
        W.v += self._vrPrime[issuerId]
        return W

    def updateWitness(self, witnessCreds: Dict[str, WitnessCredential], newAccums: Dict[str, Accumulator],
                      gAll: Dict[str, GType]):
        for key, val in witnessCreds.items():
            accum = newAccums[key]
            g = gAll[key]
            pk = self._revocationPks[key]

            oldV = val.witi.V
            newV = accum.V

            if oldV != newV:
                val.witi.V = newV

                vOldMinusNew = oldV - newV
                vNewMinusOld = newV - oldV
                omegaDenom = 1
                for j in vOldMinusNew:
                    omegaDenom *= g[pk.L + 1 - j + val.i]
                omegaNum = 1
                for j in vNewMinusOld:
                    omegaNum *= g[pk.L + 1 - j + val.i]

                val.witi.omega = val.witi.omega * omegaNum / omegaDenom

    def prepareProofNonVerification(self, witnessCreds: Dict[str, WitnessCredential],
                                    accums: Dict[str, Accumulator], nonce) -> RevocationProof:
        CList = []
        TauList = []
        XList = ProofParams()
        cH = None

        # TODO: it works for one issuer only now
        for key, val in witnessCreds.items():
            pk = self._revocationPks[key]
            group = self._groups[key]
            accum = accums[key]

            cListParams = self._genCListParams(group, val)
            proofCList = self._createCListValues(pk, val, cListParams)
            CList.extend(proofCList.asList())

            tauListParams = self._genTauListParams(group)
            proofTauList = self.createTauListValues(pk, accum, tauListParams, proofCList)
            TauList.extend(proofTauList.asList())

            cH = get_hash_hex(nonce, *reduce(lambda x, y: x + y, [TauList, CList]), group=group)
            chNum_z = hex_hash_to_ZR(cH, group)

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

    def testProof(self, witnessCreds: Dict[str, WitnessCredential], accums: Dict[str, Accumulator]):
        for key, val in witnessCreds.items():
            pk = self._revocationPks[key]
            group = self._groups[key]
            accum = accums[key]

            cListParams = self._genCListParams(group, val)
            proofCList = self._createCListValues(pk, val, cListParams)
            proofTauList = self.createTauListValues(pk, accum, cListParams, proofCList)

            proofTauListCalc = ProofRevocationBuilder.createTauListExpectedValues(pk, accum, proofCList)

            if proofTauListCalc.asList() != proofTauList.asList():
                raise ValueError("revocation proof is incorrect")

        return True

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
