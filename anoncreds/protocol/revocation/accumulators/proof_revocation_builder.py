from typing import Dict

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair

from anoncreds.protocol.revocation.accumulators.accumulator_definition import RevocationPublicKey
from anoncreds.protocol.types import CredDefPublicKey
from anoncreds.protocol.revocation.accumulators.types import RevocationPublicKey, RevocationSecretKey, \
    Accumulator, AccumulatorPublicKey, AccumulatorSecretKey, \
    Witness, WitnessCredential, GType
from anoncreds.protocol.globals import LARGE_MASTER_SECRET

class ProofCListParams:
    def __init__(self, rho, rhoPrime, r, rPrime, rPrimePrime, rPrimePrimePrime, o, oPrime,
                 m, mPrime, t, tPrime):
        self.rho = rho
        self.rhoPrime = rhoPrime
        self.r = r
        self.rPrime = rPrime
        self.rPrimePrime = rPrimePrime
        self.rPrimePrimePrime = rPrimePrimePrime
        self.o = o
        self.oPrime = oPrime
        self.m = m
        self.mPrime = mPrime
        self.t = t
        self.tPrime = tPrime

class ProofTauListParams:
    def __init__(self, tildeRho, tildeO, tildeOPrime, tildeC, tildeM, tildeMPrime, tildeT, tildeTPrime, tildeMR,
                 tildeS, tildeR, tildeRPrime, tildeRPrimePrime, tildeRPrimePrimePrime):
        self.tildeRho = tildeRho
        self.tildeO = tildeO
        self.tildeOPrime = tildeOPrime
        self.tildeC =tildeC
        self.tildeM = tildeM
        self.tildeMPrime = tildeMPrime
        self.tildeT = tildeT
        self.tildeTPrime = tildeTPrime
        self.tildeMR = tildeMR
        self.tildeS =tildeS
        self.tildeR = tildeR
        self.tildeRPrime = tildeRPrime
        self.tildeRPrimePrime = tildeRPrimePrime
        self.tildeRPrimePrimePrime = tildeRPrimePrimePrime


class ProofCList:
    def __init__(self, E, D, A, G, W, S, U):
        self.E = E
        self.D = D
        self.A = A
        self.G = G
        self.W = W
        self.S = S
        self.U = U

    def asList(self):
        return [self.E, self.D, self.A, self.G, self.W, self.S, self.U]


class ProofTauList:
    def __init__(self, T1, T2, T3, T4, T5, T6, T7, T8):
        self.T1 = T1
        self.T2 = T2
        self.T3 = T3
        self.T4 = T4
        self.T5 = T5
        self.T6 = T6
        self.T7 = T7
        self.T8 = T8

    def asList(self):
        return [self.T1, self.T2, self.T3, self.T4, self.T5, self.T6, self.T7, self.T8]


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


    @property
    def vrPrime(self):
        return self._vrPrime


    def testWitnessCredential(self, Ws: Dict[str, WitnessCredential], accs: Dict[str, Accumulator]):
        result = True
        for key, val in Ws.items():
            result &= self.testWitnessCredential(key, val, accs[key])
        return result


    def testWitnessCredential(self, issuerId,  W: WitnessCredential, acc: Accumulator):
        W = self._getPresentationWitnessCredential(issuerId, W)

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


    def _getPresentationWitnessCredential(self, issuerId, W: WitnessCredential):
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


    def proofNonVerification(self, witnessCreds: Dict[str, WitnessCredential], accums: Dict[str, Accumulator], nonce):
        CList = []
        TauList = []

        for key, val in witnessCreds.items():
            pk = self._vrPrime[key]
            group = self._groups[key]
            accum = accums[key]

            cListParams = self._genCListParams(group, val)
            proofCList = self._createCListValues(pk, val, cListParams)
            CList.extend(proofCList.asList())

            tauListParams = self._genTauListParams(group)
            proofTauList = self._createTauListValues(pk, accum, tauListParams, proofCList)
            TauList.extend(proofTauList.asList())



    def _genCListParams(self, group, w: WitnessCredential) -> ProofCListParams:
        rho = group.random(ZR)
        rhoPrime = group.random(ZR)
        r = group.random(ZR)
        rPrime = group.random(ZR)
        rPrimePrime = group.random(ZR)
        rPrimePrimePrime = group.random(ZR)
        o = group.random(ZR)
        oPrime = group.random(ZR)
        m = rho * w.c
        mPrime = r * w.c
        t = o * w.c
        tPrime = oPrime * w.c
        return ProofCListParams(rho, rhoPrime, r, rPrime, rPrimePrime, rPrimePrimePrime, o, oPrime, m, mPrime, t, tPrime)

    def _createCListValues(self, pk: RevocationPublicKey, w: WitnessCredential, params: ProofCListParams) -> ProofCList:
        E = (pk.h ** params.rho) * (pk.htilde ** params.o)
        D = (pk.g ** params.r) * (pk.htilde ** params.oPrime)
        A = w.sigma * (pk.htilde ** params.rho)
        G = w.gi * (pk.htilde ** params.r)
        W = w.witi.omega * (pk.htilde ** params.rPrime)
        S = w.witi.sigmai * (pk.htilde ** params.rPrimePrime)
        U = w.witi.ui * (pk.htilde ** params.rPrimePrimePrime)
        return ProofCList(E, D, A, G, W, S, U)

    def _genTauListParams(self, group) -> ProofTauListParams:
        tildeRho = group.random(ZR)
        tildeO = group.random(ZR)
        tildeOPrime = group.random(ZR)
        tildeC = group.random(ZR)
        tildeM = group.random(ZR)
        tildeMPrime = group.random(ZR)
        tildeT = group.random(ZR)
        tildeTPrime = group.random(ZR)
        tildeMR = group.random(ZR)
        tildeS = group.random(ZR)
        tildeR = group.random(ZR)
        tildeRPrime = group.random(ZR)
        tildeRPrimePrime = group.random(ZR)
        tildeRPrimePrimePrime = group.random(ZR)
        return ProofTauListParams(tildeRho, tildeO, tildeOPrime, tildeC, tildeM, tildeMPrime, tildeT, tildeTPrime,
                                  tildeMR, tildeS, tildeR, tildeRPrime, tildeRPrimePrime, tildeRPrimePrimePrime)


    def _createTauListValues(self, pk: RevocationPublicKey, accum: Accumulator, params: ProofTauListParams,
                             proofC: ProofCList) -> ProofTauList:
        T1 = (pk.h ** params.tildeRho) * (pk.htilde ** params.tildeO)
        T2 = (proofC.E ** params.tildeC) * (pk.h ** (-params.tildeM)) * (pk.htilde ** (-params.tildeT))
        T3 = (pair(proofC.A, pk.h) ** params.tildeC) * \
             (pair(pk.htilde, pk.h) ** params.tildeR) * \
             (pair(pk.htilde, pk.y) ** -params.tildeRho) * \
             (pair(pk.htilde, pk.h) ** -params.tildeM) * \
             (pair(pk.h1, pk.h) ** -params.tildeMR) * \
             (pair(pk.h2, pk.h) ** -params.tildeS)
        T4 = (pair(pk.htilde, accum.acc) ** params.tildeR) * \
             (pair(1 / pk.g, pk.htilde) ** params.tildeRPrime)
        T5 = (pk.g ** params.tildeR) * (pk.htilde ** params.tildeOPrime)
        T6 = (proofC.D ** params.tildeC) * (pk.g ** -params.tildeMPrime) * (pk.htilde ** -params.tildeTPrime)
        T7 = (pair(pk.pk * proofC.G, pk.htilde) ** params.tildeRPrimePrime) * \
             (pair(pk.htilde, pk.htilde) ** -params.tildeMPrime) * \
             (pair(pk.htilde, proofC.S) ** params.tildeR)
        T8 = (pair(pk.htilde, pk.u) ** params.tildeR) * \
             (pair(1 / pk.g, pk.htilde) ** params.tildeRPrimePrimePrime)
        return ProofTauList(T1, T2, T3, T4, T5, T6, T7, T8)


    def testProof(self, witnessCreds: Dict[str, WitnessCredential], accums: Dict[str, Accumulator]):
        for key, val in witnessCreds.items():
            pk = self._revocationPks[key]
            group = self._groups[key]
            accum = accums[key]

            cListParams = self._genCListParams(group, val)
            proofCList = self._createCListValues(pk, val, cListParams)
            tauListParams = ProofTauListParams(cListParams.rho, cListParams.o, cListParams.oPrime, val.c,
                                               cListParams.m, cListParams.mPrime, cListParams.t, cListParams.tPrime,
                                               self._ms, val.v, cListParams.r, cListParams.rPrime,
                                               cListParams.rPrimePrime, cListParams.rPrimePrimePrime)
            proofTauList = self._createTauListValues(pk, accum, tauListParams, proofCList)

            TCalc = [proofCList.E,
                     pk.h/pk.h,
                     pair(pk.h0 * proofCList.G, pk.h) / pair(proofCList.A, pk.y),
                     pair(proofCList.G, accum.acc) / pair(pk.g, proofCList.W) * accum.pk.z,
                     proofCList.D,
                     pk.h/pk.h,
                     pair(pk.pk * proofCList.G, proofCList.S) / pair(pk.g, pk.g),
                     pair(proofCList.G, pk.u) / pair(pk.g, proofCList.U)]

            l = proofTauList.asList()
            for i in range(8):
                if (l[i] != TCalc[i]):
                    print()
                    print(i)
                    print(l[i])
                    print (TCalc[i])

            if TCalc != proofTauList.asList():
                raise ValueError("revocation proof is incorrect")

        return True