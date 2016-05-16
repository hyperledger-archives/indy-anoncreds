from charm.core.math.integer import integer, randomBits
from protocol.utils import get_hash
from protocol.globals import lestart, lnonce


class Verifier:
    def __init__(self, pk_i):
        self.pk_i = pk_i

    @property
    def Nonce(self):
        nv = integer(randomBits(lnonce))

        return nv

    def verify_proof(self, proof, nonce, attrs):
        c, evect, vvect, mvect, Aprime, Ar, Aur = proof
        Z = self.pk_i["Z"]
        S = self.pk_i["S"]
        N = self.pk_i["N"]
        R = self.pk_i["R"]

        x = 1 % N
        Rur = x
        for key, val in Aur.items():
            Rur *= R[str(key)] ** mvect[str(key)]

        Rr = x
        for key, val in Ar.items():
            Rr *= R[str(key)] ** attrs[str(key)]

        denom = (Rr * (Aprime ** (2 ** lestart)))
        Tvect1 = (Z / denom) ** (-1 * c)
        Tvect2 = (Aprime ** evect)
        Tvect3 = (S ** vvect)
        Tvect = (Tvect1 * Tvect2 * Rur * Tvect3) % N

        cvect = integer(get_hash(Aprime, Tvect, nonce))

        return c == cvect
