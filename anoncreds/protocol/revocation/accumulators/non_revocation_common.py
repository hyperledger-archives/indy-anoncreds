from anoncreds.protocol.types import Accumulator, NonRevocProofXList, \
    NonRevocProofCList, RevocationPublicKey, \
    NonRevocProofTauList, AccumulatorPublicKey
from anoncreds.protocol.utils import groupIdentityG1
from config.config import cmod


def createTauListValues(pk: RevocationPublicKey, accum: Accumulator,
                        params: NonRevocProofXList,
                        proofC: NonRevocProofCList) -> NonRevocProofTauList:
    T1 = (pk.h ** params.rho) * (pk.htilde ** params.o)
    T2 = (proofC.E ** params.c) * (pk.h ** (-params.m)) * (
        pk.htilde ** (-params.t))
    T3 = ((cmod.pair(proofC.A, pk.hhat) ** params.c) *
          (cmod.pair(pk.htilde, pk.hhat) ** params.r)) / \
         ((cmod.pair(pk.htilde, pk.y) ** params.rho) *
          (cmod.pair(pk.htilde, pk.hhat) ** params.m) *
          (cmod.pair(pk.h1, pk.hhat) ** params.m2) *
          (cmod.pair(pk.h2, pk.hhat) ** params.s))
    T4 = (cmod.pair(pk.htilde, accum.acc) ** params.r) * \
         (cmod.pair(1 / pk.g, pk.hhat) ** params.rPrime)
    T5 = (pk.g ** params.r) * (pk.htilde ** params.oPrime)
    T6 = (proofC.D ** params.rPrimePrime) * (pk.g ** -params.mPrime) * (
        pk.htilde ** -params.tPrime)
    T7 = (cmod.pair(pk.pk * proofC.G, pk.hhat) ** params.rPrimePrime) * \
         (cmod.pair(pk.htilde, pk.hhat) ** -params.mPrime) * \
         (cmod.pair(pk.htilde, proofC.S) ** params.r)
    T8 = (cmod.pair(pk.htilde, pk.u) ** params.r) * \
         (cmod.pair(1 / pk.g, pk.hhat) ** params.rPrimePrimePrime)
    return NonRevocProofTauList(T1, T2, T3, T4, T5, T6, T7, T8)


def createTauListExpectedValues(pk: RevocationPublicKey, accum: Accumulator,
                                accumPk: AccumulatorPublicKey,
                                proofC: NonRevocProofCList) -> NonRevocProofTauList:
    T1 = proofC.E
    T2 = groupIdentityG1()
    T3 = cmod.pair(pk.h0 * proofC.G, pk.hhat) / cmod.pair(proofC.A, pk.y)
    T4 = cmod.pair(proofC.G, accum.acc) / (
        cmod.pair(pk.g, proofC.W) * accumPk.z)
    T5 = proofC.D
    T6 = groupIdentityG1()
    T7 = cmod.pair(pk.pk * proofC.G, proofC.S) / cmod.pair(pk.g, pk.gprime)
    T8 = cmod.pair(proofC.G, pk.u) / cmod.pair(pk.g, proofC.U)
    return NonRevocProofTauList(T1, T2, T3, T4, T5, T6, T7, T8)
