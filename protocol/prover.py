from charm.core.math.integer import randomBits, integer

from protocol.globals import lvprime, lmvect, lestart, letilde, lvtilde
from protocol.utils import get_hash


class Prover:

    def __init__(self, pk_i):
        """
        Create a prover instance
        :param pk_i: The public key of the Issuer
        """
        self.m = {}
        self.pk_i = pk_i
        self._vprime = randomBits(lvprime)

        S = self.pk_i["S"]
        n = self.pk_i["N"]
        self._U = (S ** self._vprime) % n

    def set_attrs(self, attrs):
        self.m = attrs

    def prepare_proof(self, credential, revealed_attrs, nonce):
        attrs = credential["encodedAttrs"]
        A = credential["A"]
        e = credential["e"]
        v = credential["v"]

        # Revealed attributes
        Ar = {}
        # Unrevealed attributes
        Aur = {}

        N = self.pk_i["N"]
        S = self.pk_i["S"]
        R = self.pk_i["R"]

        for key, val in attrs.items():
            if key in revealed_attrs:
                Ar[key] = val
            else:
                Aur[key] = val

        mtilde = {}
        for key, val in Aur.items():
            mtilde[str(key)] = integer(randomBits(lmvect))

        Ra = integer(randomBits(lvprime))

        Aprime = A * (S ** Ra) % N
        vprime = (v - e * Ra)
        eprime = e - (2 ** lestart)

        etilde = integer(randomBits(letilde))
        vtilde = integer(randomBits(lvtilde))

        Rur = 1 % N

        for key, val in Aur.items():
            Rur = Rur * (R[str(key)] ** mtilde[str(key)])

        T = ((Aprime ** etilde) * Rur * (S ** vtilde)) % N

        c = integer(get_hash(Aprime, T, nonce))

        evect = etilde + (c * eprime)
        vvect = vtilde + (c * vprime)

        mvect = {}
        for key, val in Aur.items():
            mvect[str(key)] = mtilde[str(key)] + (c * attrs[str(key)])

        return c, evect, vvect, mvect, Aprime, Ar, Aur

    @property
    def U(self):
        return self._U

    @property
    def vprime(self):
        return self._vprime

