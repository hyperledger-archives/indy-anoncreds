from typing import Set, Dict

from charm.core.math.integer import integer

VType = Set[int]
GType = Dict[int, integer]

class RevocationPublicKey:
    def __init__(self, qr, g, h, h0, h1, h2, htilde, u, pk, y, L):
        self.qr = qr
        self.g = g
        self.h = h
        self.h0 = h0
        self.h1 = h1
        self.h2 = h2
        self.htilde = htilde
        self.u = u
        self.pk = pk
        self.L = L
        self.y = y


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
    def __init__(self, acc, V: VType, pk: AccumulatorPublicKey):
        self.acc = acc
        self.V = V
        self.pk = pk


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
