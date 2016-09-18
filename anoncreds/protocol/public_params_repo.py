from abc import abstractmethod

from charm.core.math.integer import randomPrime, randomBits, isPrime, random

from anoncreds.protocol.globals import LARGE_PUBLIC_RHO, LARGE_PUBLIC_B
from anoncreds.protocol.types import PublicParams

class PublicParamsRepo:
    @abstractmethod
    def getParams(self) -> PublicParams:
        raise NotImplementedError


class InMemoryPublicParamsRepo(PublicParamsRepo):
    def __init__(self):
        self.rho, self.b, self.Gamma = self._genRhoBGamma()
        self.g = self._genG()
        self.h = self._genH()


    def _genRhoBGamma(self):
        while True:
            rho= randomPrime(LARGE_PUBLIC_RHO)
            b = randomBits(LARGE_PUBLIC_B)
            Gamma = b*rho + 1
            if (isPrime(Gamma) and (rho % b !=0)):
                return (rho, b, Gamma)

    def _genG(self):
        while True:
            gprime = random(self.Gamma)
            g = (gprime ** self.b) % self.Gamma
            if (g != 1):
                return g

    def _genH(self):
        r = random(self.rho)
        return self.g ** self.r


    def getParams(self) -> PublicParams:
        return PublicParams(self.Gamma, self.rho, self.g, self.h)
