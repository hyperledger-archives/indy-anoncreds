import hashlib
from charm.core.math.integer import randomBits, integer

class Prover:
    "Idemix prover"

    def __init__(self, pk_i):
        """
        Create a prover instance
        :param pk_i: The public key of the Issuer
        """
        self.m = {}
        self.pk_i = pk_i
        self._vprime = randomBits(2048)

        S = self.pk_i["S"]
        n = self.pk_i["N"]
        self._U = (S ** self._vprime) % n

    def set_attrs(self, attrs):
        self.m = attrs

    def prepare_proof(self, attrs, revealed_attrs, A, e, v, nonce):
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
        for i in range(1, len(Aur)):
            mtilde[str(i)] = randomBits(592)

        Ra = randomBits(2128)

        Aprime = A * (S ** Ra) % N
        vprime = integer(v - e * Ra)
        eprime = e - (2 ** 596)

        etilde = randomBits(456)
        vtilde = randomBits(3060)

        Rur = 1 % N

        for i in range(1, len(Aur)):
            Rur = Rur * (R[str(i)] ** mtilde[str(i)])

        T = (Aprime ** etilde) * Rur * (S ** vtilde) % N

        h_challenge = hashlib.sha256()
        h_challenge.update(T, Aprime, nonce)
        c = h_challenge.digest()

        evect = etilde - c * eprime
        vvect = vtilde + c * vprime

        mvect = {}
        for i, val in Aur.items():
            mvect[str(i)] = mtilde[str(i)] + c * attrs[str(i)]

        return c, evect, vvect, mvect, Aprime, Ar, Aur

    @property
    def U(self):
        return self._U

    @property
    def vprime(self):
        return self._vprime

