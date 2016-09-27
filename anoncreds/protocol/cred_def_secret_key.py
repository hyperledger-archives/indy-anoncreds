from charm.core.math.integer import integer, random as charm_random

from anoncreds.protocol.utils import genPrime


class CredDefSecretKey:
    def __init__(self, p: integer=None, q: integer=None):
        self._p = p if p else genPrime() * 2 + 1
        self._q = q if q else genPrime() * 2 + 1
        self._n = self.p * self.q

    @classmethod
    def fromStr(cls, serializedSK):
        p, q = serializedSK.split(",")
        return cls(integer(int(p)), integer(int(q)))

    @property
    def p(self):
        return self._p

    @property
    def q(self):
        return self._q

    @property
    def n(self):
        return self._n

    @property
    def p_prime(self):
        return (self.p - 1) / 2

    @property
    def q_prime(self):
        return (self.q - 1) / 2

    def __str__(self) -> str:
        return "{},{}".format(int(self.p), int(self.q))

    def __eq__(self, other):
        return self.p == other.p and self.q == other.q

    def genX(self):
        maxValue = self.p_prime * self.q_prime - 1
        minValue = 2
        return integer(charm_random(maxValue - minValue)) + minValue
