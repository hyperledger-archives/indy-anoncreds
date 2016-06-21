from charm.core.math.integer import integer, randomBits
from functools import reduce
from anoncreds.protocol.utils import get_hash, get_values_of_dicts, \
    splitRevealedAttributes
from anoncreds.protocol.globals import lestart, lnonce, iterations


class Verifier:
    def __init__(self):
        self.interactionDetail = {}  # Dict[String, String]
        self.credDefs = {}           # Dict[(issuer id, credential name, credential version), Credential Definition]

    def generateNonce(self, interationId):
        nv = integer(randomBits(lnonce))
        self.interactionDetail[str(nv)] = interationId
        return nv

    def _getFromLocal(self, proof):
        issuerId = ''  # TODO: get issuerId from proof
        credName = ''  # TODO: get credName from proof
        credVersion = ''  # TODO: get credVersion from proof
        return self.credDefs.get((issuerId, credName, credVersion))

    def _fetchAndUpdateLocalCredDef(self, issuerId, credName, credVersion):
        pkI = 'a', 'b', 'c', 'd'   #  TODO: replace with correct logic
        self.credDefs[(issuerId, credName, credVersion)] = pkI
        return pkI

    def _getIssuerPkByCredDef(self, credDef):
        keys = credDef['keys']
        R = {}
        for key, val in keys['attributes'].items():
            R[str(key)] = val
        # R["0"] is a random number needed corresponding to master secret
        R["0"] = keys['master_secret']

        pk_i = {'N': keys['n'], 'S': keys['S'], 'Z': keys['Z'], 'R': R}
        return pk_i

    def _getIssuerPk(self, proof):
        pki = self._getFromLocal(self, proof)
        if pki is None:
            pki = self._fetchAndUpdateLocalCredDef(self, proof)
        return pki

    def verify_proof(self, proof, nonce, attrs, revealedAttrs):
        """
        Verify the proof
        :param attrs: The encoded attributes dictionary
        :param revealedAttrs: The revealed attributes list
        :param nonce: The nonce used to have a commit
        :param encodedAttrsDict: The dictionary for encoded attributes
        :return: A boolean with the verification status for the proof
        """

        flatAttrs = {x: y for z in attrs.values() for x, y in z.items()}

        Ar, Aur = splitRevealedAttributes(flatAttrs, revealedAttrs)


        Tvect = {}
        # Extract the values from the proof
        c, evect, vvect, mvect, Aprime = proof

        pk_i = self._getIssuerPk(proof)

        for key, val in pk_i.items():
            Z = pk_i[key]["Z"]
            S = pk_i[key]["S"]
            N = pk_i[key]["N"]
            R = pk_i[key]["R"]
            includedAttrs = attrs[key]

            x = 1 % N
            Rur = x
            for k, v in Aur.items():
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

        # Calculate the `cvect` value based on proof.
        # This value is mathematically proven to be equal to `c`
        # if proof is created correctly from credentials. Refer 2.8 in document
        cvect = integer(get_hash(*get_values_of_dicts(Aprime, Tvect,
                                                      {"nonce": nonce})))

        return c == cvect

    def verifyPredicateProof(self, proof, nonce, attrs, revealedAttrs,
                             predicate):
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

        flatAttrs = {x: y for z in attrs.values() for x, y in z.items()}

        Ar, Aur = splitRevealedAttributes(flatAttrs, revealedAttrs)

        pk_i = self._getIssuerPk(proof)

        for key, val in pk_i.items():
            Z = pk_i[key]["Z"]
            S = pk_i[key]["S"]
            N = pk_i[key]["N"]
            R = pk_i[key]["R"]
            includedAttrs = attrs[key]

            x = 1 % N
            Rur = x
            for k, v in Aur.items():
                if k in includedAttrs:
                    Rur *= R[str(k)] ** mvect[str(k)]
            Rur *= R["0"] ** mvect["0"]

            Rr = x
            for k, v in Ar.items():
                if k in includedAttrs:
                    Rr *= R[str(k)] ** attrs[key][str(k)]
                    #print k,attrs[str(k)]

            denom = (Rr * (Aprime[key] ** (2 ** lestart)))
            Tvect1 = (Z / denom) ** (-1 * c)
            Tvect2 = (Aprime[key] ** evect[key])
            Tvect3 = (S ** vvect[key])
            Tvect[key] = (Tvect1 * Tvect2 * Rur * Tvect3) % N
            Tau.extend(get_values_of_dicts(Tvect))

        for key, val in predicate.items():
            S = pk_i[key]["S"]
            Z = pk_i[key]["Z"]
            N = pk_i[key]["N"]
            Tval = C[key]["Tval"]

            # Iterate over the predicates for a given credential(issuer)
            for k, value in val.items():
                Tvalvect = {}

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


