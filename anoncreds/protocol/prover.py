from charm.core.math.integer import randomBits, integer
from math import sqrt, floor
from functools import reduce
from typing import Dict

from anoncreds.protocol.types import Credential
from anoncreds.protocol.globals import lvprime, lmvect, lestart, letilde, \
    lvtilde, lms, lutilde, lrtilde, lalphatilde, iterations
from anoncreds.protocol.utils import get_hash, get_values_of_dicts, \
    getUnrevealedAttrs


class Prover:

    def __init__(self, pk_i):
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
            S = val["S"]
            n = val["N"]
            R = val["R"]
            self._U[key] = (S ** self._vprime[key]) * (R["0"] ** self._ms) % n

    def setAttrs(self, attrs):
        self.m = attrs

    def prepareProof(self, credential: Dict[str, Credential],
                     attrs, revealedAttrs, nonce):
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
        tildeValues, primeValues, T = findSecretValues(attrs, unrevealedAttrs, credential, self.pk_i)
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
        mvect["0"] = mtilde["0"] + (c * self._ms)

        return c, evect, vvect, mvect, Aprime

    def preparePredicateProof(self, credential: Dict[str, Credential],
                              attrs, revealedAttrs, nonce, predicate):

        TauList = []
        CList = []
        C = {}
        evect = {}
        vvect = {}
        u = {}
        utilde = {}
        uvect = {}
        r = {}
        rvect = {}
        rtilde = {}
        alphatilde = 0
        alphavect = 0

        flatAttrs, unrevealedAttrs = getUnrevealedAttrs(attrs, revealedAttrs)
        tildeValues, primeValues, T = findSecretValues(attrs, unrevealedAttrs, credential, self.pk_i)
        mtilde, etilde, vtilde = tildeValues
        Aprime, vprime, eprime = primeValues

        for key, val in credential.items():
            TauList.append(T[key])
            CList.append(Aprime[key])
            updateObject(C, key, "Aprime", Aprime[key])

        for key, val in predicate.items():
            S = self.pk_i[key]["S"]
            Z = self.pk_i[key]["Z"]
            N = self.pk_i[key]["N"]

            # Iterate over the predicates for a given credential(issuer)
            for k, value in val.items():

                delta = flatAttrs[k] - value
                u = fourSquares(delta)

                for i in range(0, iterations):
                    r[str(i)] = integer(randomBits(lvprime))
                r["delta"] = integer(randomBits(lvprime))

                Tval = {}
                for i in range(0, iterations):
                    Tval[str(i)] = (Z ** u[i]) * (S ** r[str(i)]) % N
                    utilde[str(i)] = integer(randomBits(lutilde))
                    rtilde[str(i)] = integer(randomBits(lrtilde))
                Tval["delta"] = (Z ** delta) * (S ** r["delta"]) % N
                rtilde["delta"] = integer(randomBits(lrtilde))

                CList.extend(get_values_of_dicts(Tval))
                updateObject(C, key, "Tval", Tval)

                for i in range(0, iterations):
                    TauList.append((Z ** utilde[str(i)]) * (S ** rtilde[str(i)]) % N)
                TauList.append((Z ** mtilde[k]) * (S ** rtilde["delta"]) % N)

                alphatilde = integer(randomBits(lalphatilde))

                Q = 1 % N
                for i in range(0, iterations):
                    Q *= Tval[str(i)] ** utilde[str(i)]
                Q *= S ** alphatilde % N
                TauList.append(Q)

        c = integer(get_hash(nonce, *reduce(lambda x, y: x+y, [TauList, CList])))

        for key, val in credential.items():
            evect[key] = etilde[key] + (c * eprime[key])
            vvect[key] = vtilde[key] + (c * vprime[key])

        mvect = {}
        for k, value in unrevealedAttrs.items():
            mvect[str(k)] = mtilde[str(k)] + (c * attrs[key][str(k)])
        mvect["0"] = mtilde["0"] + (c * self._ms)

        subProofC = {"evect": evect, "vvect": vvect, "mvect": mvect, "Aprime": Aprime}

        for key, val in predicate.items():
            for a, p in val.items():
                urproduct = 0
                for i in range(0, iterations):
                    uvect[str(i)] = utilde[str(i)] + c * u[i]
                    rvect[str(i)] = rtilde[str(i)] + c * r[str(i)]
                    urproduct += u[i] * r[str(i)]
                rvect["delta"] = rtilde["delta"] + c * r["delta"]

                alphavect = alphatilde + c * (r["delta"] - urproduct)

        subProofPredicate = {"uvect": uvect, "rvect": rvect, "mvect": mvect, "alphavect": alphavect}

        return c, subProofC, subProofPredicate, C, CList

    @property
    def U(self):
        return self._U

    @property
    def vprime(self):
        return self._vprime


def findSecretValues(attrs, unrevealedAttrs, credential: Dict[str, Credential], pk):
    Aprime = {}
    vprime = {}
    eprime = {}
    etilde = {}
    vtilde = {}
    T ={}

    mtilde = {}
    for key, value in unrevealedAttrs.items():
        mtilde[key] = integer(randomBits(lmvect))
    mtilde["0"] = integer(randomBits(lmvect))

    for key, val in credential.items():
        Ra = integer(randomBits(lvprime))

        A, e, v = val
        includedAttrs = attrs[key]

        N = pk[key]["N"]
        S = pk[key]["S"]
        R = pk[key]["R"]

        Aprime[key] = A * (S ** Ra) % N
        vprime[key] = (v - e * Ra)
        eprime[key] = e - (2 ** lestart)

        etilde[key] = integer(randomBits(letilde))
        vtilde[key] = integer(randomBits(lvtilde))

        Rur = 1 % N
        for k, value in unrevealedAttrs.items():
            if k in includedAttrs:
                Rur = Rur * (R[k] ** mtilde[k])
        Rur *= R["0"] ** mtilde["0"]

        T[key] = ((Aprime[key] ** etilde[key]) * Rur * (S ** vtilde[key])) % N

    return (mtilde, etilde, vtilde), (Aprime, vprime, eprime), T


def findLargestSquareLessThan(x):
    sqrtx = int(floor(sqrt(x)))
    return sqrtx


def fourSquares(delta):
    u1 = findLargestSquareLessThan(delta)
    u2 = findLargestSquareLessThan(delta - (u1 ** 2))
    u3 = findLargestSquareLessThan(delta - (u1 ** 2) - (u2 ** 2))
    u4 = findLargestSquareLessThan(delta - (u1 ** 2) - (u2 ** 2) - (u3 ** 2))
    if (u1 ** 2) + (u2 ** 2) + (u3 ** 2) + (u4 ** 2) == delta:
        return list((u1, u2, u3, u4))
    else:
        raise Exception("Cannot get the four squares for delta {0}".format(delta))


def updateObject(obj, parentKey, key, val):
    parentVal = obj.get(parentKey, {})
    parentVal[key] = val
    obj[parentKey] = parentVal

    return obj


