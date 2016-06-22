from charm.core.math.integer import randomBits, integer
from typing import Dict

from anoncreds.protocol.globals import lvprime, lmvect, lestart, letilde, lvtilde, lms
from anoncreds.protocol.models import Credential, IssuerPublicKey
from anoncreds.protocol.utils import get_hash, get_values_of_dicts, \
    splitRevealedAttributes


class Prover:

    def __init__(self, pk_i: Dict[str, IssuerPublicKey]):
        """
        Create a prover instance
        :param pk_i: The public key of the Issuer(s)
        """
        self.m = {}

        # Generate the master secret
        self._ms = integer(randomBits(lms))

        # Set the public key of the issuers
        self.pk_i = pk_i

        self._vprime = {}
        for key, val in self.pk_i.items():
            self._vprime[key] = randomBits(lvprime)

        # Calculate the `U` values using Issuer's `S`, R["0"] and master secret
        self._U = {}
        for key, val in self.pk_i.items():
            N, R, S, Z = val
            self._U[key] = (S ** self._vprime[key]) * (R["0"] ** self._ms) % N

    def set_attrs(self, attrs):
        self.m = attrs

    def prepare_proof(self, credential: Dict[str, Credential], attrs, revealedAttrs, nonce,
                      encodedAttrsDict):
        """
        Prepare the proof from credentials
        :param credential: The credential to be used for the proof preparation.
        This is a dictionary with key as issuer name and value as the credential
        :param attrs: The encoded attributes dictionary
        :param revealedAttrs: The revealed attributes list
        :param nonce: The nonce used to have a commit
        :param encodedAttrsDict: The dictionary for encoded attributes
        :return: The proof
        """
        T = {}
        Aprime = {}
        etilde = {}
        eprime = {}
        vtilde = {}
        vprime = {}
        evect = {}
        vvect = {}

        Ar, Aur = splitRevealedAttributes(attrs, revealedAttrs)

        mtilde = {}
        for key, value in Aur.items():
            mtilde[str(key)] = integer(randomBits(lmvect))
        mtilde["0"] = integer(randomBits(lmvect))

        for key, val in credential.items():
            A, e, v = val
            N, R, S, Z = self.pk_i[key]
            includedAttrs = encodedAttrsDict[key]

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

        # Calculate the `c` value as the hash result of Aprime, T and nonce.
        # This value will be used to verify the proof against the credential
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

