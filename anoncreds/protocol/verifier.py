from charm.core.math.integer import integer, randomBits
from typing import Dict

from anoncreds.protocol.utils import get_hash, get_values_of_dicts, \
    splitRevealedAttributes
from anoncreds.protocol.globals import lestart, lnonce
from anoncreds.protocol.models import IssuerPublicKey


class Verifier:
    def __init__(self, pk_i: Dict[str, IssuerPublicKey]):
        self.pk_i = pk_i

    @property
    def Nonce(self):
        nv = integer(randomBits(lnonce))

        return nv

    def verify_proof(self, proof, nonce, attrs, revealedAttrs, encodedAttrsDict):
        """
        Verify the proof
        :param attrs: The encoded attributes dictionary
        :param revealedAttrs: The revealed attributes list
        :param nonce: The nonce used to have a commit
        :param encodedAttrsDict: The dictionary for encoded attributes
        :return: A boolean with the verification status for the proof
        """

        Ar, Aur = splitRevealedAttributes(attrs, revealedAttrs)

        Tvect = {}
        # Extract the values from the proof
        c, evect, vvect, mvect, Aprime = proof

        for key, val in self.pk_i.items():
            N, R, S, Z = val
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

        # Calculate the `cvect` value based on proof.
        # This value is mathematically proven to be equal to `c`
        # if proof is created correctly from credentials. Refer 2.8 in document
        cvect = integer(get_hash(*get_values_of_dicts(Aprime, Tvect,
                                                      {"nonce": nonce})))

        return c == cvect
