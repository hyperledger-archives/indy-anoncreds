import uuid
from functools import reduce
from math import sqrt, floor
from typing import Dict, Sequence

from charm.core.math.integer import randomBits, integer

from anoncreds.protocol.globals import LARGE_VPRIME, LARGE_MVECT, LARGE_E_START, LARGE_ETILDE, \
    LARGE_VTILDE, LARGE_MASTER_SECRET, LARGE_UTILDE, LARGE_RTILDE, LARGE_ALPHATILDE, ITERATIONS
from anoncreds.protocol.types import Credential, CredDefPublicKey,\
    PredicateProof, SubProofPredicate, T, Proof, SecretValue, TildValue, PrimeValue
from anoncreds.protocol.utils import get_hash, get_values_of_dicts, \
    getUnrevealedAttrs
from anoncreds.protocol import types


class ProofBuilder:
    def __init__(self, credDefPks: Dict[str, CredDefPublicKey], masterSecret=None):
        """
        Create a proof instance

        :param credDefPks: The public key of the Issuer(s)
        """

        self.id = str(uuid.uuid4())
        self.credential = None
        self.revealedAttrs = None
        self.nonce = None
        self.attrs = {}

        # Generate the master secret
        self._ms = masterSecret or integer(randomBits(LARGE_MASTER_SECRET))

        # Set the public key of the issuers
        self.credDefPks = credDefPks

        for key, x in self.credDefPks.items():
            self.credDefPks[key] = x.inFieldN()

        self._vprime = {}
        for key, val in self.credDefPks.items():
            self._vprime[key] = randomBits(LARGE_VPRIME)

        # Calculate the `U` values using Issuer's `S`, R["0"] and master secret
        self._U = {}
        for key, val in self.credDefPks.items():
            N = val.N
            R = val.R
            S = val.S
            Z = val.Z
            self._U[key] = (S ** self._vprime[key]) * (R["0"] ** self._ms) % N

    @property
    def masterSecret(self):
        return self._ms

    def setAttrs(self, attrs):
        self.attrs = attrs

    def setCredential(self, credential):
        self.credential = credential

    def setRevealedAttrs(self, revealedAttrs):
        self.revealedAttrs = revealedAttrs

    def setNonce(self, nonce):
        self.nonce = nonce

    def setParams(self, attrs, credential, revealedAttrs, nonce):
        self.setAttrs(attrs)
        self.setCredential(credential)
        self.setRevealedAttrs(revealedAttrs)
        self.setNonce(nonce)

    @staticmethod
    def prepareProof(pk_i, masterSecret, credential: Dict[str, Credential],
                     attrs: Dict[str, Dict[str, T]], revealedAttrs: Sequence[str],
                     nonce) -> types.Proof:
        """
        Prepare the proof from credentials

        :param credential: The credential to be used for the proof preparation.
        This is a dictionary with key as issuer name and value as the credential
        :param attrs: The encoded attributes dictionary
        :param revealedAttrs: The revealed attributes list
        :param nonce: The nonce used to have a commit
        :return: The proof
        """
        evect = {}
        vvect = {}

        flatAttrs, unrevealedAttrs = getUnrevealedAttrs(attrs, revealedAttrs)
        tildeValues, primeValues, T = findSecretValues(attrs, unrevealedAttrs, credential, pk_i)
        mtilde, etilde, vtilde = tildeValues
        Aprime, vprime, eprime = primeValues

        # Calculate the `c` value as the hash result of Aprime, T and nonce.
        # This value will be used to verify the proof against the credential
        c = integer(get_hash(*get_values_of_dicts(Aprime, T, {"nonce": nonce})))

        for key, val in credential.items():
            evect[key] = etilde[key] + (c * eprime[key])
            vvect[key] = vtilde[key] + (c * vprime[key])

        mvect = {}
        for k, value in unrevealedAttrs.items():
            mvect[str(k)] = mtilde[str(k)] + (c * flatAttrs[str(k)])
        mvect["0"] = mtilde["0"] + (c * masterSecret)

        return Proof(c, evect, mvect, vvect, Aprime)

    # FIXME This function is 100 lines long. Break it down.
    def preparePredicateProof(self, credential: Dict[str, Credential],
                              attrs: Dict[str, Dict[str, T]],
                              revealedAttrs: Sequence[str],
                              nonce, predicate: Dict[str, Dict]) -> PredicateProof:

        TauList, CList, C, u, r = [], [], {}, {}, {}
        evect, vvect, uvect, rvect, alphavect = {}, {}, {}, {}, {}
        utilde, rtilde, alphatilde = {}, {}, 0

        flatAttrs, unrevealedAttrs = getUnrevealedAttrs(attrs, revealedAttrs)
        tildeValues, primeValues, T = findSecretValues(attrs, unrevealedAttrs, credential, self.credDefPks)
        mtilde, etilde, vtilde = tildeValues
        Aprime, vprime, eprime = primeValues

        for key, val in credential.items():
            TauList.append(T[key])
            CList.append(Aprime[key])
            updateDict(C, key, "Aprime", Aprime[key])

        for key, val in predicate.items():
            x = self.credDefPks[key]

            # Iterate over the predicates for a given credential(issuer)
            for k, value in val.items():

                delta = flatAttrs[k] - value
                if delta < 0:
                    raise ValueError("Predicate is not satisfied")

                u = fourSquares(delta)

                for i in range(0, ITERATIONS):
                    r[str(i)] = integer(randomBits(LARGE_VPRIME))
                r["delta"] = integer(randomBits(LARGE_VPRIME))

                Tval = {}
                for i in range(0, ITERATIONS):
                    Tval[str(i)] = (x.Z ** u[i]) * (x.S ** r[str(i)]) % x.N
                    utilde[str(i)] = integer(randomBits(LARGE_UTILDE))
                    rtilde[str(i)] = integer(randomBits(LARGE_RTILDE))
                Tval["delta"] = (x.Z ** delta) * (x.S ** r["delta"]) % x.N
                rtilde["delta"] = integer(randomBits(LARGE_RTILDE))

                CList.extend(get_values_of_dicts(Tval))
                updateDict(C, key, "Tval", Tval)

                for i in range(0, ITERATIONS):
                    TauList.append((x.Z ** utilde[str(i)]) * (x.S ** rtilde[str(i)]) % x.N)
                TauList.append((x.Z ** mtilde[k]) * (x.S ** rtilde["delta"]) % x.N)

                alphatilde = integer(randomBits(LARGE_ALPHATILDE))

                Q = 1 % x.N
                for i in range(0, ITERATIONS):
                    Q *= Tval[str(i)] ** utilde[str(i)]
                Q *= x.S ** alphatilde % x.N
                TauList.append(Q)

        c = integer(get_hash(nonce, *reduce(lambda x, y: x+y, [TauList, CList])))

        for key, val in credential.items():
            evect[key] = etilde[key] + (c * eprime[key])
            vvect[key] = vtilde[key] + (c * vprime[key])

        mvect = {}
        for k, value in unrevealedAttrs.items():
            mvect[str(k)] = mtilde[str(k)] + (c * flatAttrs[str(k)])
        mvect["0"] = mtilde["0"] + (c * self._ms)

        subProofC = types.Proof(c, evect, mvect, vvect, Aprime)

        for key, val in predicate.items():
            for a, p in val.items():
                urproduct = 0
                for i in range(0, ITERATIONS):
                    uvect[str(i)] = utilde[str(i)] + c * u[i]
                    rvect[str(i)] = rtilde[str(i)] + c * r[str(i)]
                    urproduct += u[i] * r[str(i)]
                rvect["delta"] = rtilde["delta"] + c * r["delta"]

                alphavect = alphatilde + c * (r["delta"] - urproduct)

        subProofPredicate = SubProofPredicate(alphavect, rvect, uvect)

        return PredicateProof(subProofC, subProofPredicate, C, CList)

    @property
    def U(self):
        return self._U

    @property
    def vprime(self):
        return self._vprime


def findSecretValues(attrs: Dict[str, T], unrevealedAttrs: Dict,
                     credentials: Dict[str, Credential],
                     credDefPks: Dict[str, CredDefPublicKey]):

    def getMTilde():
        mtilde = {}
        for key, value in unrevealedAttrs.items():
            mtilde[key] = integer(randomBits(LARGE_MVECT))
        mtilde["0"] = integer(randomBits(LARGE_MVECT))
        return mtilde

    # FIXME Use unicode characters, they'll fit in one line.
    Aprime, vprime, eprime, etilde, vtilde, T = {}, {}, {}, {}, {}, {}
    mtilde = getMTilde()

    # FIXME Breakdown into several functions.
    for issuer, credential in credentials.items():
        Ra = integer(randomBits(LARGE_VPRIME))

        credDefPk = credDefPks[issuer]
        A, e, v = credential
        includedAttrs = attrs[issuer]

        Aprime[issuer] = A * (credDefPk.S ** Ra) % credDefPk.N
        vprime[issuer] = (v - e * Ra)
        eprime[issuer] = e - (2 ** LARGE_E_START)

        etilde[issuer] = integer(randomBits(LARGE_ETILDE))
        vtilde[issuer] = integer(randomBits(LARGE_VTILDE))

        Rur = 1 % credDefPk.N
        for k, value in unrevealedAttrs.items():
            if k in includedAttrs:
                Rur = Rur * (credDefPk.R[k] ** mtilde[k])
        Rur *= credDefPk.R["0"] ** mtilde["0"]

        T[issuer] = ((Aprime[issuer] ** etilde[issuer]) * Rur * (credDefPk.S ** vtilde[issuer])) % credDefPk.N

    tildValue = TildValue(mtilde, etilde, vtilde)
    primeValue = PrimeValue(Aprime, vprime, eprime)

    return SecretValue(tildValue, primeValue, T)


def largestSquareLessThan(x: int):
    sqrtx = int(floor(sqrt(x)))
    return sqrtx


def fourSquares(delta: int):
    u1 = largestSquareLessThan(delta)
    u2 = largestSquareLessThan(delta - (u1 ** 2))
    u3 = largestSquareLessThan(delta - (u1 ** 2) - (u2 ** 2))
    u4 = largestSquareLessThan(delta - (u1 ** 2) - (u2 ** 2) - (u3 ** 2))
    if (u1 ** 2) + (u2 ** 2) + (u3 ** 2) + (u4 ** 2) == delta:
        return list((u1, u2, u3, u4))
    else:
        raise Exception("Cannot get the four squares for delta {0}".format(delta))


def updateDict(obj: Dict[str, Dict[str, T]], parentKey: str,
               key: str, val: any):
    parentVal = obj.get(parentKey, {})
    parentVal[key] = val
    obj[parentKey] = parentVal

