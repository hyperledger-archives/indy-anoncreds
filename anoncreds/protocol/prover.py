from charm.core.math.integer import randomBits, integer

from anoncreds.protocol.globals import lvprime, lmvect, lestart, letilde, lvtilde, lms
from anoncreds.protocol.utils import get_hash, get_values_of_dicts


class Prover:

    def __init__(self, pk_i):
        """
        Create a prover instance
        :param pk_i: The public key of the Issuer
        """
        self.m = {}
        self._ms = integer(randomBits(lms))
        self.pk_i = pk_i
        self._vprime = {}
        for key, val in self.pk_i.items():
            self._vprime[key] = randomBits(lvprime)

        self._U = {}
        for key, val in self.pk_i.items():
            S = val["S"]
            n = val["N"]
            R = val["R"]
            self._U[key] = (S ** self._vprime[key]) * (R["0"] ** self._ms) % n

    def set_attrs(self, attrs):
        self.m = attrs

    def prepare_proof(self, credential, attrs, revealedAttrs, nonce,
                      encodedAttrsDict):
        T = {}
        Aprime = {}
        etilde = {}
        eprime = {}
        vtilde = {}
        vprime = {}
        evect = {}
        vvect = {}

        # Revealed attributes
        Ar = {}
        # Unrevealed attributes
        Aur = {}

        for key, value in attrs.items():
            if key in revealedAttrs:
                Ar[key] = value
            else:
                Aur[key] = value

        mtilde = {}
        for key, value in Aur.items():
            mtilde[str(key)] = integer(randomBits(lmvect))
        mtilde["0"] = integer(randomBits(lmvect))

        for key, val in credential.items():
            A = val["A"]
            e = val["e"]
            v = val["v"]
            includedAttrs = encodedAttrsDict[key]

            N = self.pk_i[key]["N"]
            S = self.pk_i[key]["S"]
            R = self.pk_i[key]["R"]

            Ra = integer(randomBits(lvprime))

            Aprime[key] = A * (S ** Ra) % N
            vprime[key] = (v - e * Ra)
            eprime[key] = e - (2 ** lestart)

            etilde[key] = integer(randomBits(letilde))
            vtilde[key] = integer(randomBits(lvtilde))

            Rur = 1 % N

            for k, value in Aur.items():
                if k in includedAttrs:
                    Rur = Rur * (R[str(k)] ** mtilde[str(k)])
            Rur *= R["0"] ** mtilde["0"]

            T[key] = ((Aprime[key] ** etilde[key]) * Rur * (S ** vtilde[key])) % N

        c = integer(get_hash(*get_values_of_dicts(Aprime, T, {"nonce": nonce})))

        for key, val in credential.items():
            evect[key] = etilde[key] + (c * eprime[key])
            vvect[key] = vtilde[key] + (c * vprime[key])

        mvect = {}
        for k, value in Aur.items():
            mvect[str(k)] = mtilde[str(k)] + (c * attrs[str(k)])
        mvect["0"] = mtilde["0"] + (c * self._ms)

        return c, evect, vvect, mvect, Aprime

    @property
    def U(self):
        return self._U

    @property
    def vprime(self):
        return self._vprime

