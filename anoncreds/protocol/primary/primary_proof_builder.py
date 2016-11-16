from typing import Dict, Sequence

from charm.core.math.integer import randomBits, integer

from anoncreds.protocol.globals import LARGE_VPRIME, LARGE_MVECT, LARGE_E_START, LARGE_ETILDE, \
    LARGE_VTILDE, LARGE_UTILDE, LARGE_RTILDE, LARGE_ALPHATILDE, ITERATIONS, DELTA
from anoncreds.protocol.primary.primary_proof_common import calcTge, calcTeq
from anoncreds.protocol.types import PrimaryClaim, PublicData, Predicate, PrimaryInitProof, \
    PrimaryEqualInitProof, PrimaryPrecicateGEInitProof, PrimaryProof, PrimaryEqualProof, PrimaryPredicateGEProof, \
    CredentialDefinition
from anoncreds.protocol.utils import getUnrevealedAttrs, fourSquares


class PrimaryClaimInitializer:
    def __init__(self, publicData: Dict[CredentialDefinition, PublicData], masterSecret):
        """
        Create a proof instance

        :param credDefPks: The public key of the Issuer(s)
        """

        self._ms = masterSecret
        self._data = publicData

        self._genPresentationData()

    def _genPresentationData(self):
        self._vprime = {}
        self._U = {}
        # Calculate the `U` values using Issuer's `S`, R["0"] and master secret
        for credDef, val in self._data.items():
            self._vprime[credDef] = randomBits(LARGE_VPRIME)
            N = val.pk.N
            Rms = val.pk.Rms
            S = val.pk.S
            self._U[credDef] = (S ** self._vprime[credDef]) * (Rms ** self._ms) % N

    def getU(self, credDef):
        return self._U[credDef]

    def preparePrimaryClaim(self, credDef, claim: PrimaryClaim):
        claim.v += self._vprime[credDef]
        return claim


class PrimaryProofBuilder:
    def __init__(self, publicData: Dict[CredentialDefinition, PublicData], m1):
        """
        Create a proof instance

        :param credDefPks: The public key of the Issuer(s)
        """
        self._m1 = m1
        self._data = publicData

    def initProof(self, credDef, c1: PrimaryClaim, revealedAttrs: Sequence[str], predicates: Sequence[Predicate],
                  m1Tilde, m2Tilde) -> PrimaryInitProof:
        if not c1:
            return None

        eqProof = self._initEqProof(credDef, c1, revealedAttrs, m1Tilde, m2Tilde)
        geProofs = []
        for predicate in predicates:
            geProof = self._initGeProof(credDef, eqProof, c1, predicate)
            geProofs.append(geProof)
        return PrimaryInitProof(eqProof, geProofs)

    def finalizeProof(self, credDef, cH, initProof: PrimaryInitProof) -> PrimaryProof:
        if not initProof:
            return None

        cH = integer(cH)
        eqProof = self._finalizeEqProof(credDef, cH, initProof.eqProof)
        geProofs = []
        for initGeProof in initProof.geProofs:
            geProof = self._finalizeGeProof(credDef, cH, initGeProof, eqProof)
            geProofs.append(geProof)
        return PrimaryProof(eqProof, geProofs)

    def _initEqProof(self, credDef, c1: PrimaryClaim, revealedAttrs: Sequence[str], m1Tilde, m2Tilde) \
            -> PrimaryEqualInitProof:
        m2Tilde = m2Tilde if m2Tilde else integer(randomBits(LARGE_MVECT))
        unrevealedAttrs = getUnrevealedAttrs(c1.attrs, revealedAttrs)
        mtilde = self._getMTilde(unrevealedAttrs)

        Ra = integer(randomBits(LARGE_VPRIME))
        pk = self._data[credDef].pk

        A, e, v = c1.A, c1.e, c1.v
        Aprime = A * (pk.S ** Ra) % pk.N
        vprime = (v - e * Ra)
        eprime = e - (2 ** LARGE_E_START)

        etilde = integer(randomBits(LARGE_ETILDE))
        vtilde = integer(randomBits(LARGE_VTILDE))

        Rur = 1 % pk.N
        for k, value in unrevealedAttrs.items():
            if k in c1.attrs:
                Rur = Rur * (pk.R[k] ** mtilde[k])
        Rur *= pk.Rms ** m1Tilde
        Rur *= pk.Rctxt ** m2Tilde

        # T = ((Aprime ** etilde) * Rur * (pk.S ** vtilde)) % pk.N
        T = calcTeq(pk, Aprime, etilde, vtilde, mtilde, m1Tilde, m2Tilde, unrevealedAttrs.keys())

        return PrimaryEqualInitProof(c1, Aprime, T, etilde, eprime, vtilde, vprime, mtilde, m1Tilde, m2Tilde,
                                     unrevealedAttrs.keys(), revealedAttrs)

    def _initGeProof(self, credDef, eqProof: PrimaryEqualInitProof, c1: PrimaryClaim, predicate: Predicate) \
            -> PrimaryPrecicateGEInitProof:
        # gen U for Delta
        pk = self._data[credDef].pk
        k, value = predicate.attrName, predicate.value
        delta = c1.attrs[k] - value
        if delta < 0:
            raise ValueError("Predicate is not satisfied")

        u = fourSquares(delta)

        # prepare C list
        r = {}
        T = {}
        CList = []
        for i in range(0, ITERATIONS):
            r[str(i)] = integer(randomBits(LARGE_VPRIME))
            T[str(i)] = (pk.Z ** u[str(i)]) * (pk.S ** r[str(i)]) % pk.N
            CList.append(T[str(i)])
        r[DELTA] = integer(randomBits(LARGE_VPRIME))
        T[DELTA] = (pk.Z ** delta) * (pk.S ** r[DELTA]) % pk.N
        CList.append(T[DELTA])

        # prepare Tau List
        utilde = {}
        rtilde = {}
        for i in range(0, ITERATIONS):
            utilde[str(i)] = integer(randomBits(LARGE_UTILDE))
            rtilde[str(i)] = integer(randomBits(LARGE_RTILDE))
        rtilde[DELTA] = integer(randomBits(LARGE_RTILDE))
        alphatilde = integer(randomBits(LARGE_ALPHATILDE))

        TauList = calcTge(pk, utilde, rtilde, eqProof.mTilde[k], alphatilde, T)
        return PrimaryPrecicateGEInitProof(CList, TauList, u, utilde, r, rtilde, alphatilde, predicate, T)

    def _finalizeEqProof(self, credDef, cH, initProof: PrimaryEqualInitProof) -> PrimaryEqualProof:
        e = initProof.eTilde + (cH * initProof.ePrime)
        v = initProof.vTilde + (cH * initProof.vPrime)

        m = {}
        for k in initProof.unrevealedAttrs:
            m[str(k)] = initProof.mTilde[str(k)] + (cH * initProof.c1.attrs[str(k)])
        m1 = initProof.m1Tilde + (cH * self._m1)
        m2 = initProof.m2Tilde + (cH * initProof.c1.m2)

        return PrimaryEqualProof(e, v, m, m1, m2, initProof.Aprime, initProof.revealedAttrs)

    def _finalizeGeProof(self, credDef, cH, initProof: PrimaryPrecicateGEInitProof, eqProof: PrimaryEqualProof) \
            -> PrimaryPredicateGEProof:
        u = {}
        r = {}
        urproduct = 0
        for i in range(0, ITERATIONS):
            u[str(i)] = initProof.uTilde[str(i)] + cH * initProof.u[str(i)]
            r[str(i)] = initProof.rTilde[str(i)] + cH * initProof.r[str(i)]
            urproduct += initProof.u[str(i)] * initProof.r[str(i)]
            r[DELTA] = initProof.rTilde[DELTA] + cH * initProof.r[DELTA]

        alpha = initProof.alphaTilde + cH * (initProof.r[DELTA] - urproduct)

        k, value = initProof.predicate.attrName, initProof.predicate.value
        return PrimaryPredicateGEProof(u, r, alpha, eqProof.m[str(k)], initProof.T, initProof.predicate)

    def _getMTilde(self, unrevealedAttrs):
        mtilde = {}
        for key, value in unrevealedAttrs.items():
            mtilde[key] = integer(randomBits(LARGE_MVECT))
        return mtilde
