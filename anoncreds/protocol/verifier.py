from functools import reduce
from typing import Dict, Sequence

from charm.core.math.integer import integer, randomBits

from anoncreds.protocol.cred_def_store import CredDefStore
from anoncreds.protocol.globals import LARGE_E_START, LARGE_NONCE, ITERATIONS, DELTA, TVAL, KEYS, PK_R, PK_N, PK_S, PK_Z, \
    NONCE, ZERO_INDEX
from anoncreds.protocol.issuer_key import IssuerKey
from anoncreds.protocol.issuer_key_store import IssuerKeyStore
from anoncreds.protocol.types import PredicateProof, T
from anoncreds.protocol.utils import get_hash, get_values_of_dicts, \
    splitRevealedAttrs


def getProofParams(proof, pkIssuer: Dict[str, IssuerKey],
                   attrs, revealedAttrs):

    flatAttrs = {x: y for z in attrs.values() for x, y in z.items()}
    Ar, unrevealedAttrs = splitRevealedAttrs(flatAttrs, revealedAttrs)
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
        Rur *= p.R[ZERO_INDEX] ** mvect[ZERO_INDEX]

        Rr = 1 % p.N
        for k, v in Ar.items():
            if k in includedAttrs:
                Rr *= p.R[str(k)] ** attrs[key][str(k)]

        denom = (Rr * (Aprime[key] ** (2 ** LARGE_E_START)))
        Tvect1 = (p.Z / denom) ** (-1 * c)
        Tvect2 = (Aprime[key] ** evect[key])
        Tvect3 = (p.S ** vvect[key])
        Tvect[key] = (Tvect1 * Tvect2 * Rur * Tvect3) % p.N

    return Aprime, c, Tvect


class Verifier:
    def __init__(self,
                 id,
                 credDefStore: CredDefStore,
                 issuerKeyStore: IssuerKeyStore):
        self.id = id
        self.interactionDetail = {}  # Dict[String, String]
        self.credDefStore = credDefStore
        self.issuerKeyStore = issuerKeyStore
        # DEPR
        # self.credDefs = {}           # Dict[(issuer id, credential name, credential version), Credential Definition]

    def generateNonce(self, interactionId):
        nv = integer(randomBits(LARGE_NONCE))
        self.interactionDetail[str(nv)] = interactionId
        return nv

    # DEPR
    # def _getIssuerPkByCredDef(self, credDef) -> IssuerKey:
    #     keys = credDef.fetch()[KEYS]
    #     R = {}
    #     for key, val in keys[PK_R].items():
    #         R[str(key)] = val
    #     return IssuerKey(keys[PK_N], R, keys[PK_S], keys[PK_Z])
    #
    # def getCredDef(self, issuerId, name, version):
    #     key = (issuerId, name, version)
    #     credDdef = self.credDefs.get(key)
    #     if not credDdef:
    #         credDdef = self.fetchCredDef(*key)
    #     return credDdef

    def verify(self, issuer, name, version, proof, nonce, attrs, revealedAttrs,
               credDefId, issuerKeyId):
        credDef = self.credDefStore.fetch(credDefId)
        # DEPR
        # credDef = self.fetchCredDef(issuer, name, version)
        pk = self.issuerKeyStore.fetch(issuerKeyId)
        result = Verifier.verifyProof({issuer.id: pk}, proof, nonce, attrs, revealedAttrs)
        return result

    def fetchCredDef(self, issuer, name, version):
        return issuer.getCredDef(name=name, version=version)

    def verifyPredicateProof(self, proof: PredicateProof, credDefPks, nonce,
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

        Aprime, c, Tvect = getProofParams(subProofC, credDefPks, attrs, revealedAttrs)

        Tau.extend(get_values_of_dicts(Tvect))

        for key, val in predicate.items():
            p = credDefPks[key]
            Tval = C[key][TVAL]

            # Iterate over the predicates for a given credential(issuer)
            for k, value in val.items():

                Tdeltavect1 = (Tval[DELTA] * (p.Z ** value))
                Tdeltavect2 = (p.Z ** mvect[k]) * (p.S ** rvect[DELTA])
                Tdeltavect = (Tdeltavect1 ** (-1 * c)) * Tdeltavect2 % p.N

                Tuproduct = 1 % p.N
                for i in range(0, ITERATIONS):
                    Tvalvect1 = (Tval[str(i)] ** (-1 * c))
                    Tvalvect2 = (p.Z ** uvect[str(i)])
                    Tvalvect3 = (p.S ** rvect[str(i)])
                    Tau.append(Tvalvect1 * Tvalvect2 * Tvalvect3 % p.N)
                    Tuproduct *= Tval[str(i)] ** uvect[str(i)]

                Tau.append(Tdeltavect)

                Qvect1 = (Tval[DELTA] ** (-1 * c))
                Qvect = Qvect1 * Tuproduct * (p.S ** alphavect) % p.N
                Tau.append(Qvect)

        cvect = integer(get_hash(nonce, *reduce(lambda x, y: x+y, [Tau, CList])))

        return c == cvect

    @classmethod
    def verifyProof(cls, credDefPks, proof, nonce, attrs, revealedAttrs):
        """
        Verify the proof
        :param attrs: The encoded attributes dictionary
        :param revealedAttrs: The revealed attributes list
        :param nonce: The nonce used to have a commit
        :return: A boolean with the verification status for the proof
        """

        Aprime, c, Tvect = getProofParams(proof, credDefPks, attrs, revealedAttrs)
        # Calculate the `cvect` value based on proof.
        # This value is mathematically proven to be equal to `c`
        # if proof is created correctly from credentials. Refer 2.8 in document
        cvect = integer(get_hash(*get_values_of_dicts(Aprime, Tvect,
                                                      {NONCE: nonce})))
        return c == cvect
