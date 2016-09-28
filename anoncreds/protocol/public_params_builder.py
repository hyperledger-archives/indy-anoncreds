from charm.core.math.integer import randomPrime, randomBits, isPrime, random

from anoncreds.protocol.globals import LARGE_PUBLIC_RHO, LARGE_PUBLIC_B
from anoncreds.protocol.types import PublicParams


class PublicParamsBuilder:
    def __init__(self):
        super().__init__()

    @classmethod
    def _genRhoBGamma(cls):
        while True:
            rho = randomPrime(LARGE_PUBLIC_RHO)
            b = randomBits(LARGE_PUBLIC_B)
            Gamma = b * rho + 1
            if (isPrime(Gamma) and (rho % b != 0)):
                return (rho, b, Gamma)

    @classmethod
    def _genG(cls, Gamma, b):
        while True:
            gprime = random(Gamma)
            g = (gprime ** b) % Gamma
            if (g != 1):
                return g

    @classmethod
    def generateParams(cls) -> PublicParams:
        rho, b, Gamma = PublicParamsBuilder._genRhoBGamma()
        g = PublicParamsBuilder._genG(Gamma, b)
        r = random(rho)
        h = g ** r
        return PublicParams(Gamma, rho, g, h)
