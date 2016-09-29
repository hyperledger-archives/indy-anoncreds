from functools import reduce
from typing import Dict, Sequence

from charm.core.math.integer import randomBits, integer

from anoncreds.protocol.globals import LARGE_VPRIME, LARGE_MVECT, LARGE_E_START, LARGE_ETILDE, \
    LARGE_VTILDE, LARGE_UTILDE, LARGE_RTILDE, LARGE_ALPHATILDE, ITERATIONS, APRIME, DELTA, TVAL, \
    ZERO_INDEX
from anoncreds.protocol.primary.primary_proof_common import calcTge, calcTeq
from anoncreds.protocol.types import Credential, PredicateProof, SubProofPredicate, T, Proof, PredicateProofComponent, \
    PrimaryClaim, PublicData, Predicate, PrimaryInitProof, \
    PrimaryEqualInitProof, PrimaryPrecicateGEInitProof, PrimaryProof, PrimaryEqualProof, PrimaryPredicateGEProof
from anoncreds.protocol.utils import get_hash, get_values_of_dicts, \
    getUnrevealedAttrs, updateDict, fourSquares


class PrimaryClaimInitializer:
    def __init__(self, publicData: Dict[str, PublicData], masterSecret):
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
        for issuerID, val in self._data.items():
            self._vprime[issuerID] = randomBits(LARGE_VPRIME)
            N = val.pk.N
            Rms = val.pk.Rms
            S = val.pk.S
            self._U[issuerID] = (S ** self._vprime[issuerID]) * (Rms ** self._ms) % N

    def getU(self, issuerId):
        return self._U[issuerId]

    def preparePrimaryClaim(self, issuerId, claim: PrimaryClaim):
        claim.v += self._vprime[issuerId]
        return claim


class PrimaryProofBuilder:
    def __init__(self, publicData: Dict[str, PublicData], m1):
        """
        Create a proof instance

        :param credDefPks: The public key of the Issuer(s)
        """
        self._m1 = m1
        self._data = publicData

    def initProof(self, issuerId, c1: PrimaryClaim, revealedAttrs: Sequence[str], predicates: Sequence[Predicate],
                  m1Tilde, m2Tilde) -> PrimaryInitProof:
        if not c1:
            return None

        eqProof = self._initEqProof(issuerId, c1, revealedAttrs, m1Tilde, m2Tilde)
        geProofs = []
        for predicate in predicates:
            geProof = self._initGeProof(issuerId, eqProof, c1, predicate)
            geProofs.append(geProof)
        return PrimaryInitProof(eqProof, geProofs)

    def finalizeProof(self, issuerId, cH, initProof: PrimaryInitProof) -> PrimaryProof:
        if not initProof:
            return None

        cH = integer(cH)
        eqProof = self._finalizeEqProof(issuerId, cH, initProof.eqProof)
        geProofs = []
        for initGeProof in initProof.geProofs:
            geProof = self._finalizeGeProof(issuerId, cH, initGeProof, eqProof)
            geProofs.append(geProof)
        return PrimaryProof(eqProof, geProofs)

    def _initEqProof(self, issuerId, c1: PrimaryClaim, revealedAttrs: Sequence[str], m1Tilde, m2Tilde) \
            -> PrimaryEqualInitProof:
        m2Tilde = m2Tilde if m2Tilde else integer(randomBits(LARGE_MVECT))
        unrevealedAttrs = getUnrevealedAttrs(c1.attrs, revealedAttrs)
        mtilde = self._getMTilde(unrevealedAttrs)

        Ra = integer(randomBits(LARGE_VPRIME))
        pk = self._data[issuerId].pk

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

    def _initGeProof(self, issuerId, eqProof: PrimaryEqualInitProof, c1: PrimaryClaim, predicate: Predicate) \
            -> PrimaryPrecicateGEInitProof:
        # gen U for Delta
        pk = self._data[issuerId].pk
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

    def _finalizeEqProof(self, issuerId, cH, initProof: PrimaryEqualInitProof) -> PrimaryEqualProof:
        e = initProof.eTilde + (cH * initProof.ePrime)
        v = initProof.vTilde + (cH * initProof.vPrime)

        m = {}
        for k in initProof.unrevealedAttrs:
            m[str(k)] = initProof.mTilde[str(k)] + (cH * initProof.c1.attrs[str(k)])
        m1 = initProof.m1Tilde + (cH * self._m1)
        m2 = initProof.m2Tilde + (cH * initProof.c1.m2)

        return PrimaryEqualProof(e, v, m, m1, m2, initProof.Aprime, initProof.revealedAttrs)

    def _finalizeGeProof(self, issuerId, cH, initProof: PrimaryPrecicateGEInitProof, eqProof: PrimaryEqualProof) \
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

    def prepareProofPredicateGreaterEq(self,
                                       creds: Dict[str, Credential],
                                       attrs: Dict[str, Dict[str, T]],
                                       revealedAttrs: Sequence[str],
                                       nonce,
                                       predicate: Dict[str, Dict]) -> PredicateProof:

        def initProofComponent(attrs, creds, revealedAttrs):
            proofComponent = PredicateProofComponent()
            proofComponent.flatAttrs, proofComponent.unrevealedAttrs = getUnrevealedAttrs(attrs, revealedAttrs)
            proofComponent.tildeValues, proofComponent.primeValues, proofComponent.T = self._findSecretValues(
                attrs,
                proofComponent.unrevealedAttrs,
                creds)
            return proofComponent

        def appendToProofCompWithCredData(proofComponent, creds):
            for key, _ in creds.items():
                proofComponent.TauList.append(proofComponent.T[key])
                proofComponent.CList.append(proofComponent.primeValues.Aprime[key])
                updateDict(proofComponent.C, key, APRIME, proofComponent.primeValues.Aprime[key])

        def appendToProofCompWithPredicateData(proofComponent, predicate):
            for key, val in predicate.items():
                x = self.credDefPks[key]
                # Iterate over the predicates for a given credential(issuer)
                for k, value in val.items():

                    delta = proofComponent.flatAttrs[k] - value
                    if delta < 0:
                        raise ValueError("Predicate is not satisfied")

                    proofComponent.u = fourSquares(delta)

                    for i in range(0, ITERATIONS):
                        proofComponent.r[str(i)] = integer(randomBits(LARGE_VPRIME))
                    proofComponent.r[DELTA] = integer(randomBits(LARGE_VPRIME))

                    Tval = {}
                    for i in range(0, ITERATIONS):
                        Tval[str(i)] = (x.Z ** proofComponent.u[i]) * (x.S ** proofComponent.r[str(i)]) % x.N
                        proofComponent.utilde[str(i)] = integer(randomBits(LARGE_UTILDE))
                        proofComponent.rtilde[str(i)] = integer(randomBits(LARGE_RTILDE))
                    Tval[DELTA] = (x.Z ** delta) * (x.S ** proofComponent.r[DELTA]) % x.N
                    proofComponent.rtilde[DELTA] = integer(randomBits(LARGE_RTILDE))

                    proofComponent.CList.extend(get_values_of_dicts(Tval))
                    updateDict(proofComponent.C, key, TVAL, Tval)

                    for i in range(0, ITERATIONS):
                        proofComponent.TauList.append(
                            (x.Z ** proofComponent.utilde[str(i)]) * (
                                x.S ** proofComponent.rtilde[str(i)]) % x.N)
                    proofComponent.TauList.append(
                        (x.Z ** proofComponent.tildeValues.mtilde[k]) * (
                            x.S ** proofComponent.rtilde[DELTA]) % x.N)

                    proofComponent.alphatilde = integer(randomBits(LARGE_ALPHATILDE))

                    Q = 1 % x.N
                    for i in range(0, ITERATIONS):
                        Q *= Tval[str(i)] ** proofComponent.utilde[str(i)]
                    Q *= x.S ** proofComponent.alphatilde % x.N
                    proofComponent.TauList.append(Q)

            proofComponent.c = integer(get_hash(nonce, *reduce(lambda x, y: x + y, [proofComponent.TauList,
                                                                                    proofComponent.CList])))

        def getSubProof(creds, predProofComponent):
            for key, val in creds.items():
                predProofComponent.evect[key] = predProofComponent.tildeValues.etilde[key] + (
                    predProofComponent.c * predProofComponent.primeValues.eprime[key])
                predProofComponent.vvect[key] = predProofComponent.tildeValues.vtilde[key] + (
                    predProofComponent.c * predProofComponent.primeValues.vprime[key])

            predProofComponent.mvect = {}
            for k, value in predProofComponent.unrevealedAttrs.items():
                predProofComponent.mvect[str(k)] = predProofComponent.tildeValues.mtilde[str(k)] + (
                    predProofComponent.c * predProofComponent.flatAttrs[str(k)])

            predProofComponent.mvect[ZERO_INDEX] = predProofComponent.tildeValues.mtilde[ZERO_INDEX] + (
                predProofComponent.c * self._ms)

            return Proof(predProofComponent.c, predProofComponent.evect, predProofComponent.mvect,
                         predProofComponent.vvect, predProofComponent.primeValues.Aprime)

        def getSubProofPredicate(predProofComponent, predicate):
            for key, val in predicate.items():
                for _, _ in val.items():
                    urproduct = 0
                    for i in range(0, ITERATIONS):
                        predProofComponent.uvect[str(i)] = predProofComponent.utilde[str(i)] + predProofComponent.c * \
                                                                                               predProofComponent.u[i]
                        predProofComponent.rvect[str(i)] = predProofComponent.rtilde[str(i)] + predProofComponent.c * \
                                                                                               predProofComponent.r[
                                                                                                   str(i)]
                        urproduct += predProofComponent.u[i] * predProofComponent.r[str(i)]

                    predProofComponent.rvect[DELTA] = predProofComponent.rtilde[DELTA] + predProofComponent.c * \
                                                                                         predProofComponent.r[DELTA]

                    predProofComponent.alphavect = predProofComponent.alphatilde + predProofComponent.c * (
                        predProofComponent.r[DELTA] - urproduct)

            return SubProofPredicate(predProofComponent.alphavect, predProofComponent.rvect,
                                     predProofComponent.uvect)

        # Add VPrime to V
        creds = self._getPresentationToken(creds)

        # Initialize predicate proof components
        proofComponent = initProofComponent(attrs, creds, revealedAttrs)

        # Modify predicate proof components based on received creds
        appendToProofCompWithCredData(proofComponent, creds)

        # Modify predicate proof component based on predicate data
        appendToProofCompWithPredicateData(proofComponent, predicate)

        # Build sub proof
        subProofC = getSubProof(creds, proofComponent)

        # Build sub proof predicate
        subProofPredicate = getSubProofPredicate(proofComponent, predicate)

        return PredicateProof(subProofC, subProofPredicate, proofComponent.C, proofComponent.CList)
