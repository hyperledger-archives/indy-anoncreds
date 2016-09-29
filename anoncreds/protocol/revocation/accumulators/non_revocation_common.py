from charm.toolbox.pairinggroup import pair

from anoncreds.protocol.types import Accumulator, NonRevocProofXList, NonRevocProofCList, RevocationPublicKey, \
    NonRevocProofTauList, AccumulatorPublicKey


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
