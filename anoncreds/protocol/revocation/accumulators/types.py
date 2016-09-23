from typing import Set, Dict, Sequence

from charm.core.math.integer import integer
from charm.toolbox.pairinggroup import ZR

VType = Set[int]
GType = Dict[int, integer]


class RevocationPublicKey:
    def __init__(self, qr, g, h, h0, h1, h2, htilde, u, pk, y, x, groupType):
        self.qr = qr
        self.g = g
        self.h = h
        self.h0 = h0
        self.h1 = h1
        self.h2 = h2
        self.htilde = htilde
        self.u = u
        self.pk = pk
        self.y = y
        self.x = x
        self.groupType = groupType


class RevocationSecretKey:
    def __init__(self, x, sk):
        self.x = x
        self.sk = sk


class AccumulatorPublicKey:
    def __init__(self, z):
        self.z = z


class AccumulatorSecretKey:
    def __init__(self, gamma):
        self.gamma = gamma


class RevocationCredential:
    def __init__(self, iA, sigma, vrPrimeprime, witi, gi, i):
        self.iA = iA
        self.sigma = sigma
        self.vrPrimeprime = vrPrimeprime
        self.witi = witi
        self.gi = gi
        self.i = i


class Accumulator:
    def __init__(self, iA, acc, V: VType, pk: AccumulatorPublicKey, L):
        self.iA = iA
        self.acc = acc
        self.V = V
        self.pk = pk
        self.L = L
        self.currentI = 1

    def isFull(self):
        return self.currentI > self.L


class Witness:
    def __init__(self, sigmai, ui, gi, omega, V: VType):
        self.sigmai = sigmai
        self.ui = ui
        self.gi = gi
        self.omega = omega
        self.V = V


class WitnessCredential:
    def __init__(self, proverId, sigma, c, v, witi: Witness, gi, i):
        self.proverId = proverId
        self.sigma = sigma
        self.c = c
        self.v = v
        self.witi = witi
        self.gi = gi
        self.i = i


class ProofParams:
    def __init__(self, rho=None, r=None, rPrime=None, rPrimePrime=None, rPrimePrimePrime=None, o=None, oPrime=None,
                 m=None, mPrime=None, t=None, tPrime=None, mR=None, s=None, c=None, group=None):
        self.rho = self._setValue(rho, group)
        self.r = self._setValue(r, group)
        self.rPrime = self._setValue(rPrime, group)
        self.rPrimePrime = self._setValue(rPrimePrime, group)
        self.rPrimePrimePrime = self._setValue(rPrimePrimePrime, group)
        self.o = self._setValue(o, group)
        self.oPrime = self._setValue(oPrime, group)
        self.m = self._setValue(m, group)
        self.mPrime = self._setValue(mPrime, group)
        self.t = self._setValue(t, group)
        self.tPrime = self._setValue(tPrime, group)
        self.mR = self._setValue(mR, group)
        self.s = self._setValue(s, group)
        self.c = self._setValue(c, group)

    def _setValue(self, v=None, group=None):
        return v if v else group.random(ZR) if group else None

    def asList(self):
        return [self.rho, self.o, self.c, self.oPrime, self.m, self.mPrime, self.t, self.tPrime,
                self.mR, self.s, self.r, self.rPrime, self.rPrimePrime, self.rPrimePrimePrime]

    def fromList(self, values: Sequence):
        self.rho, self.o, self.c, self.oPrime, self.m, self.mPrime, self.t, self.tPrime, \
        self.mR, self.s, self.r, self.rPrime, self.rPrimePrime, self.rPrimePrimePrime = tuple(values)


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


class RevocationProof:
    def __init__(self, cH, XList: ProofParams, CList: ProofCList):
        self.cH = cH
        self.XList = XList
        self.CList = CList
