from charm.core.math.integer import integer, randomBits

from anoncreds.protocol.utils import get_hash, get_values_of_dicts
from anoncreds.protocol.globals import lestart, lnonce


class Verifier:
    def __init__(self, pk_i):
        self.pk_i = pk_i

    @property
    def Nonce(self):
        nv = integer(randomBits(lnonce))

        return nv

    def verify_proof(self, proof, nonce, attrs, revealedAttrs, encodedAttrsDict):
        # Revealed attributes
        Ar = {}
        # Unrevealed attributes
        Aur = {}

        for k, value in attrs.items():
            if k in revealedAttrs:
                Ar[k] = value
            else:
                Aur[k] = value

        Tvect = {}
        c, evect, vvect, mvect, Aprime = proof

        for key, val in self.pk_i.items():
            Z = self.pk_i[key]["Z"]
            S = self.pk_i[key]["S"]
            N = self.pk_i[key]["N"]
            R = self.pk_i[key]["R"]
            includedAttrs = encodedAttrsDict[key]

            x = 1 % N
            Rur = x
            for k, v in Aur.items():
                if k in includedAttrs:
                    Rur *= R[str(k)] ** mvect[str(k)]
            Rur *= R["0"] ** mvect["0"]

            Rr = x
            for k, v in Ar.items():
                if k in includedAttrs:
                    Rr *= R[str(k)] ** attrs[str(k)]

            denom = (Rr * (Aprime[key] ** (2 ** lestart)))
            Tvect1 = (Z / denom) ** (-1 * c)
            Tvect2 = (Aprime[key] ** evect[key])
            Tvect3 = (S ** vvect[key])
            Tvect[key] = (Tvect1 * Tvect2 * Rur * Tvect3) % N

        cvect = integer(get_hash(*get_values_of_dicts(Aprime, Tvect,
                                                      {"nonce": nonce})))

        return c == cvect
