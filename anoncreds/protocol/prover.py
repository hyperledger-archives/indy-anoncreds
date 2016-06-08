from charm.core.math.integer import randomBits, integer
from math import sqrt, floor

from anoncreds.protocol.globals import lvprime, lmvect, lestart, letilde, \
    lvtilde, lms, lutilde, lrtilde, lalphatilde
from anoncreds.protocol.utils import get_hash, get_values_of_dicts


class Prover:

    def __init__(self, pk_i):
        """
        Create a prover instance
        :param pk_i: The public key of the Issuer
        """
        self.m = {}
        self._ms = integer(randomBits(lms))
        self.pk_i = pk_i
        self._vprime = {}
        for key, val in self.pk_i.items():
            self._vprime[key] = randomBits(lvprime)

        self._U = {}
        for key, val in self.pk_i.items():
            S = val["S"]
            n = val["N"]
            R = val["R"]
            self._U[key] = (S ** self._vprime[key]) * (R["0"] ** self._ms) % n

    def set_attrs(self, attrs):
        self.m = attrs

    def prepare_proof(self, credential, attrs, revealedAttrs, nonce,
                      encodedAttrsDict):
        T = {}
        Aprime = {}
        etilde = {}
        eprime = {}
        vtilde = {}
        vprime = {}
        evect = {}
        vvect = {}

        # Revealed attributes
        Ar = {}
        # Unrevealed attributes
        Aur = {}

        for key, value in attrs.items():
            if key in revealedAttrs:
                Ar[key] = value
            else:
                Aur[key] = value

        mtilde = {}
        for key, value in Aur.items():
            mtilde[str(key)] = integer(randomBits(lmvect))
        mtilde["0"] = integer(randomBits(lmvect))

        for key, val in credential.items():
            A = val["A"]
            e = val["e"]
            v = val["v"]
            includedAttrs = encodedAttrsDict[key]

            N = self.pk_i[key]["N"]
            S = self.pk_i[key]["S"]
            R = self.pk_i[key]["R"]

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

        c = integer(get_hash(*get_values_of_dicts(Aprime, T, {"nonce": nonce})))

        for key, val in credential.items():
            evect[key] = etilde[key] + (c * eprime[key])
            vvect[key] = vtilde[key] + (c * vprime[key])

        mvect = {}
        for k, value in Aur.items():
            mvect[str(k)] = mtilde[str(k)] + (c * attrs[str(k)])
        mvect["0"] = mtilde["0"] + (c * self._ms)

        return c, evect, vvect, mvect, Aprime

    def preparePredicateProof(self, credential, attrs, revealedAttrs, nonce,
                              predicate, encodedAttrsDict):
        # Revealed attributes
        Ar = {}
        # Unrevealed attributes
        Aur = {}

        Tau = {}
        C = {}
        T = {}
        Aprime = {}
        vprime = {}
        eprime = {}
        etilde = {}
        vtilde = {}
        evect = {}
        vvect = {}
        uvect = {}
        u = {}
        utilde = {}
        r = {}
        rtilde = {}
        rvect = {}
        alphatilde = 0
        alphavect = 0
        iterations = 4

        for key, value in attrs.items():
            if key in revealedAttrs:
                Ar[key] = value
            else:
                Aur[key] = value

        mtilde = {}
        for key, value in Aur.items():
            mtilde[key] = integer(randomBits(lmvect))
        mtilde["0"] = integer(randomBits(lmvect))

        for key, val in credential.items():
            Ra = integer(randomBits(lvprime))

            A = val["A"]
            e = val["e"]
            v = val["v"]
            includedAttrs = encodedAttrsDict[key]

            N = self.pk_i[key]["N"]
            S = self.pk_i[key]["S"]
            R = self.pk_i[key]["R"]

            Aprime[key] = A * (S ** Ra) % N
            vprime[key] = (v - e * Ra)
            eprime[key] = e - (2 ** lestart)

            etilde[key] = integer(randomBits(letilde))
            vtilde[key] = integer(randomBits(lvtilde))

            Rur = 1 % N

            for k, value in Aur.items():
                if k in includedAttrs:
                    Rur = Rur * (R[k] ** mtilde[k])
            Rur *= R["0"] ** mtilde["0"]

            T[key] = ((Aprime[key] ** etilde[key]) * Rur * (S ** vtilde[key])) % N

            # Tau = updateObject(Tau, key, "T", T)
            # C = updateObject(C, key, "Aprime", Aprime[key])

        Tau["T"] = T
        C["Aprime"] = Aprime

        for key, val in predicate.items():
            #TODO: Remove the hardcoded value for 'gvt'
            S = self.pk_i['gvt']["S"]
            Z = self.pk_i['gvt']["Z"]

            delta = self.m[key] - predicate[key]
            u = fourSquares(delta)

            for i in range(0, iterations):
                r[str(i)] = integer(randomBits(lvprime))
            r["delta"] = integer(randomBits(lvprime))

            Tval = {}
            for i in range(0, iterations):
                Tval[str(i)] = (Z ** u[0]) * (S ** r[str(i)]) % N
                utilde[str(i)] = integer(randomBits(lutilde))
                rtilde[str(i)] = integer(randomBits(lrtilde))
            Tval["delta"] = (Z ** delta) * (S ** r["delta"]) % N
            rtilde["delta"] = integer(randomBits(lrtilde))

            C["Tval"] = Tval

            Tbar = {}
            for i in range(0, iterations):
                Tbar[str(i)] = (Z ** utilde[str(i)]) * (S ** rtilde[str(i)]) % N
            Tbar["delta"] = (Z ** Aur[key]) * (S ** rtilde["delta"]) % N

            Tau["Tbar"] = Tbar

            alphatilde = integer(randomBits(lalphatilde))

            Q = 1 % N
            for i in range(0, iterations):
                Q *= Tval[str(i)] ** utilde[str(i)]
            Q *= S ** alphatilde

            Tau["Q"] = Q

        c = integer(get_hash(*get_values_of_dicts(Tau, C, {"nonce": nonce})))

        for key, val in credential.items():
            evect[key] = etilde[key] + (c * eprime[key])
            vvect[key] = vtilde[key] + (c * vprime[key])

        mvect = {}
        for k, value in Aur.items():
            mvect[str(k)] = mtilde[str(k)] + (c * attrs[str(k)])
        mvect["0"] = mtilde["0"] + (c * self._ms)

        subProofC = {"evect": evect, "vvect": vvect, "mvect": mvect, "Aprime": Aprime}

        for key, val in predicate.items():
            urproduct = 0
            for i in range(0, iterations):
                uvect[str(i)] = utilde[str(i)] + c * u[str(i)]
                rvect[str(i)] = rtilde[str(i)] + c * r[str(i)]
                urproduct += u[str(i)] * r[str(i)]
            rvect["delta"] = rtilde["delta"] + c * r["delta"]

            alphavect = alphatilde + c * (r["delta"] - urproduct)

        subProofPredicate = {"uvect": uvect, "rvect": rvect, "mvect": mvect, "alphavect": alphavect}

        return c, subProofC, subProofPredicate, C


    @property
    def U(self):
        return self._U


    @property
    def vprime(self):
        return self._vprime


def findLargestSquareLessThan(x):
    sqrtx = floor(sqrt(x))
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


def updateObject(obj, parent, key, val):
    if not parent in obj:
        parentVal = {}
    parentVal[key] = val
    obj[parent] = parentVal
    return obj


