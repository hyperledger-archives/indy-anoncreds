from functools import reduce
from typing import Dict, Sequence

from charm.core.math.integer import integer, randomBits

from anoncreds.protocol.globals import lestart, lnonce, iterations
from anoncreds.protocol.types import IssuerPublicKey
from anoncreds.protocol.types import PredicateProof, T
from anoncreds.protocol.utils import get_hash, get_values_of_dicts, \
    splitRevealedAttributes


def verify_proof(pk_i, proof, nonce, attrs, revealedAttrs):
    """
    Verify the proof
    :param attrs: The encoded attributes dictionary
    :param revealedAttrs: The revealed attributes list
    :param nonce: The nonce used to have a commit
    :return: A boolean with the verification status for the proof
    """
    Aprime, c, Tvect = getProofParams(proof, pk_i, attrs, revealedAttrs)
    # Calculate the `cvect` value based on proof.
    # This value is mathematically proven to be equal to `c`
    # if proof is created correctly from credentials. Refer 2.8 in document
    cvect = integer(get_hash(*get_values_of_dicts(Aprime, Tvect,
                                                  {"nonce": nonce})))
    return c == cvect


class Verifier:
    def __init__(self, id):
        self.id = id
        self.interactionDetail = {}  # Dict[String, String]
        self.credDefs = {}           # Dict[(issuer id, credential name, credential version), Credential Definition]

    def generateNonce(self, interactionId):
        nv = integer(randomBits(lnonce))
        self.interactionDetail[str(nv)] = interactionId
        return nv

    # def _getFromLocal(self, proof):
    #     issuerId = ''  # TODO: get issuerId from proof
    #     credName = ''  # TODO: get credName from proof
    #     credVersion = ''  # TODO: get credVersion from proof
    #     return self.credDefs.get((issuerId, credName, credVersion))

    # def _fetchAndUpdateLocalCredDef(self, issuerId, credName, credVersion):
    #     credDef = self.fetchCredDef(issuerId, credName, credVersion)
    #     pk = self._getIssuerPkByCredDef(credDef)
    #     self.credDefs[(issuerId, credName, credVersion)] = pk
    #     return pkI

    def _getIssuerPkByCredDef(self, credDef) -> IssuerPublicKey:
        keys = credDef.get()['keys']
        R = {}
        for key, val in keys['R'].items():
            R[str(key)] = val
        pk_i = IssuerPublicKey(keys['N'], R, keys['S'], keys['Z'])
        return pk_i

    # def _getIssuerPk(self, proof):
    #     pki = self._getFromLocal(self, proof)
    #     if pki is None:
    #         pki = self._fetchAndUpdateLocalCredDef(self, proof)
    #     return pki

    def getCredDef(self, issuerId, name, version):
        key = (issuerId, name, version)
        credDdef = self.credDefs.get(key)
        if not credDdef:
            credDdef = self.fetchCredDef(*key)
        return credDdef

    def verify(self, issuerId, name, version, proof, nonce, attrs, revealedAttrs):
        credDef = self.fetchCredDef(issuerId, name, version)
        pk = self._getIssuerPkByCredDef(credDef)
        result = verify_proof({issuerId: pk}, proof, nonce, attrs, revealedAttrs)
        return result

    def fetchCredDef(self, issuerId, name, version):
        raise NotImplementedError

    def sendStatus(self, proverId, status):
        raise NotImplementedError

    def verifyPredicateProof(self, proof: PredicateProof, pk_i, nonce,
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

        Aprime, c, Tvect = getProofParams(subProofC, pk_i, attrs, revealedAttrs)

        Tau.extend(get_values_of_dicts(Tvect))

        for key, val in predicate.items():
            p = pk_i[key]
            Tval = C[key]["Tval"]

            # Iterate over the predicates for a given credential(issuer)
            for k, value in val.items():

                Tdeltavect1 = (Tval["delta"] * (p.Z ** value))
                Tdeltavect2 = (p.Z ** mvect[k]) * (p.S ** rvect["delta"])
                Tdeltavect = (Tdeltavect1 ** (-1 * c)) * Tdeltavect2 % p.N

                Tuproduct = 1 % p.N
                for i in range(0, iterations):
                    Tvalvect1 = (Tval[str(i)] ** (-1 * c))
                    Tvalvect2 = (p.Z ** uvect[str(i)])
                    Tvalvect3 = (p.S ** rvect[str(i)])
                    Tau.append(Tvalvect1 * Tvalvect2 * Tvalvect3 % p.N)
                    Tuproduct *= Tval[str(i)] ** uvect[str(i)]

                Tau.append(Tdeltavect)

                Qvect1 = (Tval["delta"] ** (-1 * c))
                Qvect = Qvect1 * Tuproduct * (p.S ** alphavect) % p.N
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
        p = pkIssuer[key].inFieldN()
        includedAttrs = attrs[key]

        Rur = 1 % p.N
        for k, v in unrevealedAttrs.items():
            if k in includedAttrs:
                Rur *= p.R[str(k)] ** mvect[str(k)]
        Rur *= p.R["0"] ** mvect["0"]

        Rr = 1 % p.N
        for k, v in Ar.items():
            if k in includedAttrs:
                Rr *= p.R[str(k)] ** attrs[key][str(k)]

        denom = (Rr * (Aprime[key] ** (2 ** lestart)))
        Tvect1 = (p.Z / denom) ** (-1 * c)
        Tvect2 = (Aprime[key] ** evect[key])
        Tvect3 = (p.S ** vvect[key])
        Tvect[key] = (Tvect1 * Tvect2 * Rur * Tvect3) % p.N

    return Aprime, c, Tvect


