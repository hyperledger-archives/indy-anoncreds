from charm.core.math.integer import integer, randomBits
from functools import reduce
from typing import Dict, Sequence

from anoncreds.protocol.types import IssuerPublicKey, Proof, PredicateProof, T
from anoncreds.protocol.utils import get_hash, get_values_of_dicts, \
    splitRevealedAttributes
from anoncreds.protocol.globals import lestart, lnonce, iterations


class Verifier:
    def __init__(self, pk_i: Dict[str, IssuerPublicKey]):
        self.pk_i = pk_i

    @property
    def Nonce(self):
        nv = integer(randomBits(lnonce))

        return nv

    def verifyProof(self, proof: Proof, nonce,
                    attrs: Dict[str, Dict[str, T]],
                    revealedAttrs: Sequence[str]):
        """
        Verify the proof
        :param attrs: The encoded attributes dictionary
        :param revealedAttrs: The revealed attributes list
        :param nonce: The nonce used to have a commit
        :return: A boolean with the verification status for the proof
        """
        Aprime, c, Tvect = getProofParams(proof, self.pk_i, attrs, revealedAttrs)

        # Calculate the `cvect` value based on proof.
        # This value is mathematically proven to be equal to `c`
        # if proof is created correctly from credentials. Refer 2.8 in document
        cvect = integer(get_hash(*get_values_of_dicts(Aprime, Tvect,
                                                      {"nonce": nonce})))

        return c == cvect

    def verifyPredicateProof(self, proof: PredicateProof, nonce,
                             attrs: Dict[str, Dict[str, T]],
                             revealedAttrs: Sequence[str],
                             predicate: Dict[str, Sequence[str]]):
        """
        Verify the proof for Predicate implementation
        :param proof: The proof which is a combination of sub-proof for credential and proof, C
        :param nonce: The nonce used
        :param attrs: The encoded attributes
        :param revealedAttrs: The list of revealed attributes
        :param predicate: The predicate to be validated
        :return:
        """
        Tau = []
        subProofC, subProofPredicate, C, CList = proof

        # Get all the random and prime numbers for verifying the proof
        c, evect, mvect, vvect, Aprime = subProofC
        alphavect, rvect, uvect = subProofPredicate

        Aprime, c, Tvect = getProofParams(subProofC, self.pk_i, attrs, revealedAttrs)

        Tau.extend(get_values_of_dicts(Tvect))

        for key, val in predicate.items():
            N, R, S, Z = self.pk_i[key]
            Tval = C[key]["Tval"]

            # Iterate over the predicates for a given credential(issuer)
            for k, value in val.items():

                Tdeltavect1 = (Tval["delta"] * (Z ** value))
                Tdeltavect2 = (Z ** mvect[k]) * (S ** rvect["delta"])
                Tdeltavect = (Tdeltavect1 ** (-1 * c)) * Tdeltavect2 % N

                Tuproduct = 1 % N
                for i in range(0, iterations):
                    Tvalvect1 = (Tval[str(i)] ** (-1 * c))
                    Tvalvect2 = (Z ** uvect[str(i)])
                    Tvalvect3 = (S ** rvect[str(i)])
                    Tau.append(Tvalvect1 * Tvalvect2 * Tvalvect3 % N)
                    Tuproduct *= Tval[str(i)] ** uvect[str(i)]

                Tau.append(Tdeltavect)

                Qvect1 = (Tval["delta"] ** (-1 * c))
                Qvect = Qvect1 * Tuproduct * (S ** alphavect) % N
                Tau.append(Qvect)

        cvect = integer(get_hash(nonce, *reduce(lambda x, y: x+y, [Tau, CList])))

        return c == cvect


def getProofParams(proof, pkIssuer: Dict[str, IssuerPublicKey],
                   attrs, revealedAttrs):
    flatAttrs = {x: y for z in attrs.values() for x, y in z.items()}

    Ar, unrevealedAttrs = splitRevealedAttributes(flatAttrs, revealedAttrs)

    Tvect = {}
    # Extract the values from the proof
    c, evect, mvect, vvect, Aprime = proof

    for key, val in pkIssuer.items():
        N, R, S, Z = pkIssuer[key]
        includedAttrs = attrs[key]

        x = 1 % N
        Rur = x
        for k, v in unrevealedAttrs.items():
            if k in includedAttrs:
                Rur *= R[str(k)] ** mvect[str(k)]
        Rur *= R["0"] ** mvect["0"]

        Rr = x
        for k, v in Ar.items():
            if k in includedAttrs:
                Rr *= R[str(k)] ** attrs[key][str(k)]

        denom = (Rr * (Aprime[key] ** (2 ** lestart)))
        Tvect1 = (Z / denom) ** (-1 * c)
        Tvect2 = (Aprime[key] ** evect[key])
        Tvect3 = (S ** vvect[key])
        Tvect[key] = (Tvect1 * Tvect2 * Rur * Tvect3) % N

    return Aprime, c, Tvect


