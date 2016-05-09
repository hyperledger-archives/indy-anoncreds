from charm.core.math.integer import integer, randomBits
from protocol.utils import get_hash

class Verifier:
    def __init__(self, pk_i):
        self.pk_i = pk_i

    def get_nonce(self):
        nv = integer(randomBits(80))

        return nv

    def verify_proof(self, proof, nonce, attrs):
        c, evect, vvect, mvect, Aprime, Ar, Aur = proof
        Z = self.pk_i["Z"]
        S = self.pk_i["S"]
        N = self.pk_i["N"]
        R = self.pk_i["R"]

        Rur = 1 % N
        for key, val in Aur.items():
            Rur = Rur * (R[str(key)] ** mvect[str(key)])

        Rr = 1 % N
        for key, val in Ar.items():
            Rr = Rr * (R[str(key)] ** attrs[str(key)])

        denom = (Rr * (Aprime ** (2 ** 596)))
        Tvect1 = (Z / denom) ** (-1 * c)
        Tvect2 = (Aprime ** evect)
        Tvect3 = (S ** vvect)
        Tvect = (Tvect1 * Tvect2 * Rur * Tvect3) % N

        cvect = integer(get_hash(Aprime, Tvect, nonce))

        return c == cvect
