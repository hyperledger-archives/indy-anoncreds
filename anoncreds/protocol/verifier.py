from charm.core.math.integer import integer, randomBits
from functools import reduce
from anoncreds.protocol.utils import get_hash, get_values_of_dicts, \
    splitRevealedAttributes
from anoncreds.protocol.globals import lestart, lnonce, iterations


class Verifier:
    def __init__(self, pk_i):
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

        # Calculate the `cvect` value based on proof.
        # This value is mathematically proven to be equal to `c`
        # if proof is created correctly from credentials. Refer 2.8 in document
        cvect = integer(get_hash(*get_values_of_dicts(Aprime, Tvect,
                                                      {"nonce": nonce})))

        return c == cvect

    def verifyPredicateProof(self, proof, nonce, attrs, revealedAttrs,
                             predicate, encodedAttrsDict):
        """
        Verify the proof for Predicate implementation
        :param proof: The proof which is a combination of sub-proof for credential and proof, C
        :param nonce: The nonce used
        :param attrs: The encoded attributes
        :param revealedAttrs: The list of revealed attributes
        :param predicate: The predicate to be validated
        :param encodedAttrsDict: The encoded dictionary for attributes
        :return:
        """
        Tvect = {}
        Tau = []
        c, subProofC, subProofPredicate, C, CList = proof

        Aprime = subProofC["Aprime"]
        evect = subProofC["evect"]
        mvect = subProofC["mvect"]
        vvect = subProofC["vvect"]
        alphavect = subProofPredicate["alphavect"]
        rvect = subProofPredicate["rvect"]
        uvect = subProofPredicate["uvect"]


        Ar, Aur = splitRevealedAttributes(attrs, revealedAttrs)

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

            Tau.extend(get_values_of_dicts(Tvect))

        for key, val in predicate.items():
            S = self.pk_i[key]["S"]
            Z = self.pk_i[key]["Z"]
            N = self.pk_i[key]["N"]
            Tval = C[key]["Tval"]

            # Iterate over the predicates for a given credential(issuer)
            for k, value in val.items():
                Tdeltavect1 = (Tval["delta"] * (Z ** value))
                Tdeltavect2 = (Z ** mvect[k]) * (S ** rvect["delta"])
                Tdeltavect = (Tdeltavect1 ** (-1 * c)) * Tdeltavect2 % N



                Tvalvect = {}
                Tuproduct = 1 % N
                for i in range(0, iterations):
                    Tvalvect1 = (Tval[str(i)] ** (-1 * c))
                    Tvalvect2 = (Z ** uvect[str(i)])
                    Tvalvect3 = (S ** rvect[str(i)])
                    Tvalvect[str(i)] = Tvalvect1 * Tvalvect2 * Tvalvect3 % N
                    Tuproduct *= Tval[str(i)] ** uvect[str(i)]
                Tau.extend(get_values_of_dicts(Tvalvect))

                Tau.append(Tdeltavect)

                Qvect1 = (Tval["delta"] ** (-1 * c))
                Qvect = Qvect1 * Tuproduct * (S ** alphavect) % N
                Tau.append(Qvect)

        cvect = integer(get_hash(nonce, *reduce(lambda x, y: x+y, [Tau, CList])))

        return c == cvect


