from charm.core.math.integer import integer, randomBits
from protocol.utils import get_hash

class Verifier:
    def __init__(self, pk_i):
        self.pk_i = pk_i

    def get_nonce(self):
        nv = integer(randomBits(80))

        return nv

    def verify_proof(self, proof, nonce):
        #TODO: Remove exporting Ar and Aur
        c, evect, vvect, mvect, Aprime, Ar, Aur = proof
        Z = self.pk_i["Z"]
        S = self.pk_i["S"]
        N = self.pk_i["N"]
        R = self.pk_i["R"]

        Rur = 1 % N
        for i in range(1, len(Aur)):
            Rur = Rur * (R[str[i]] ** mvect[str[i]])

        Rr = 1 % N
        for i in range(1, len(Aur)):
            Rr = Rr * (R[str[i]] ** mvect[str[i]])

        q = Z / (Rr * (Aprime ** (2 ** 596)))
        Tvect = (q ** (c ** -1)) * (Aprime ** evect) * Rur * (S ** vvect) % N

        cvect = get_hash(Aprime, Tvect, nonce)

        return c == cvect
