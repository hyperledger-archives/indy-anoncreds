import uuid
from functools import reduce
from typing import Dict, Sequence

from charm.core.math.integer import randomBits, integer

from anoncreds.protocol import types
from anoncreds.protocol.globals import LARGE_VPRIME, LARGE_MVECT, LARGE_E_START, LARGE_ETILDE, \
    LARGE_VTILDE, LARGE_MASTER_SECRET, LARGE_UTILDE, LARGE_RTILDE, LARGE_ALPHATILDE, ITERATIONS, APRIME, DELTA, TVAL, \
    NONCE, ZERO_INDEX, C_VALUE, EVECT, MVECT, VVECT, ISSUER, PROOF
from anoncreds.protocol.types import Credential, CredDefPublicKey,\
    PredicateProof, SubProofPredicate, T, Proof, SecretValue, TildValue, PrimeValue, ProofComponent, \
    PredicateProofComponent
from anoncreds.protocol.utils import get_hash, get_values_of_dicts, \
    getUnrevealedAttrs, strToCharmInteger, updateDict, fourSquares


class ProofBuilder:
    def __init__(self, credDefPks: Dict[str, CredDefPublicKey], masterSecret=None):
        """
        Create a proof instance

        :param credDefPks: The public key of the Issuer(s)
        """

        self.id = str(uuid.uuid4())
        self.credential = None

        # Generate the master secret
        self._ms = masterSecret or integer(randomBits(LARGE_MASTER_SECRET))

        # Set the credential definition pub keys
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
            R0 = val.R0
            S = val.S
            self._U[key] = (S ** self._vprime[key]) * (R0 ** self._ms) % N


    @property
    def U(self):
        return self._U

    @property
    def vprime(self):
        return self._vprime



    def prepareProofFromDict(self, proofElements) -> Proof:
        issuer = proofElements[ISSUER]
        prf = proofElements[PROOF]
        prfArgs = {}
        prfArgs[APRIME] = {issuer: strToCharmInteger(prf[APRIME][issuer])}
        prfArgs[C_VALUE] = strToCharmInteger(prf[C_VALUE])
        prfArgs[EVECT] = {issuer: strToCharmInteger(prf[EVECT][issuer])}
        prfArgs[MVECT] = {k: strToCharmInteger(v) for k, v in prf[MVECT].items()}
        prfArgs[VVECT] = {issuer: strToCharmInteger(prf[VVECT][issuer])}
        return Proof(**prfArgs)


    def prepareProofAsDict(issuer,
                           creds: Dict[str, Credential],
                           encodedAttrs: Dict[str, Dict[str, T]], revealedAttrs: Sequence[str],
                           nonce) -> dict:
        prf = ProofBuilder.prepareProofEquality(creds, encodedAttrs, revealedAttrs, nonce)
        proof = {}
        proof[APRIME] = {issuer: str(prf.Aprime[issuer])}
        proof[C_VALUE] = str(prf.c)
        proof[EVECT] = {issuer: str(prf.evect[issuer])}
        proof[MVECT] = {k: str(v) for k, v in prf.mvect.items()}
        proof[VVECT] = {issuer: str(prf.vvect[issuer])}
        return proof


    def prepareProofEquality(self,
                     creds: Dict[str, Credential],
                     encodedAttrs: Dict[str, Dict[str, T]],
                     revealedAttrs: Sequence[str],
                     nonce) -> types.Proof:
        """
        Prepare the proof from credentials

        :param creds: This is a dictionary with key as issuer name and value as the credential
        :param encodedAttrs: The encoded attributes dictionary
        :param revealedAttrs: The revealed attributes list
        :param nonce: The nonce used to have a commit
        :return: The proof
        """

        def initProofComponent(credDefPks, creds, encodedAttrs, revealedAttrs, nonce):
            proofComponent = ProofComponent()
            proofComponent.flatAttrs, proofComponent.unrevealedAttrs = getUnrevealedAttrs(encodedAttrs, revealedAttrs)
            proofComponent.tildeValues, proofComponent.primeValues, proofComponent.T = self._findSecretValues(encodedAttrs,
                                                                                   proofComponent.unrevealedAttrs, creds)

            # Calculate the `c` value as the hash result of Aprime, T and nonce.
            # This value will be used to verify the proof against the credential
            proofComponent.c = integer(get_hash(*get_values_of_dicts(proofComponent.primeValues.Aprime, proofComponent.T, {NONCE: nonce})))
            return proofComponent

        # Add VPrime to V
        creds = self._getPresentationToken(creds)

        proofComponent = initProofComponent(self.credDefPks, creds, encodedAttrs, revealedAttrs, nonce)


        for credIssuer, _ in creds.items():
            proofComponent.evect[credIssuer] = proofComponent.tildeValues.etilde[credIssuer] + (proofComponent.c * proofComponent.primeValues.eprime[credIssuer])
            proofComponent.vvect[credIssuer] = proofComponent.tildeValues.vtilde[credIssuer] + (proofComponent.c * proofComponent.primeValues.vprime[credIssuer])

        for k, _ in proofComponent.unrevealedAttrs.items():
            proofComponent.mvect[str(k)] = proofComponent.tildeValues.mtilde[str(k)] + (proofComponent.c * proofComponent.flatAttrs[str(k)])
        proofComponent.mvect[ZERO_INDEX] = proofComponent.tildeValues.mtilde[ZERO_INDEX] + (proofComponent.c * self._ms)

        return Proof(proofComponent.c, proofComponent.evect, proofComponent.mvect, proofComponent.vvect, proofComponent.primeValues.Aprime)


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

                    predProofComponent.rvect[DELTA] = predProofComponent.rtilde[DELTA] + predProofComponent.c * predProofComponent.r[DELTA]

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



    def _findSecretValues(self,
                         encodedAttrs: Dict[str, T],
                         unrevealedAttrs: Dict,
                         creds: Dict[str, Credential]):

        def getMTilde(unrevealedAttrs):
            mtilde = {}
            for key, value in unrevealedAttrs.items():
                mtilde[key] = integer(randomBits(LARGE_MVECT))
            mtilde[ZERO_INDEX] = integer(randomBits(LARGE_MVECT))
            return mtilde

        def getRur(credDefPk, includedAttrs, mtilde, unrevealedAttrs):
            Rur = 1 % credDefPk.N
            for k, value in unrevealedAttrs.items():
                if k in includedAttrs:
                    Rur = Rur * (credDefPk.R[k] ** mtilde[k])
            Rur *= credDefPk.R0 ** mtilde[ZERO_INDEX]
            return Rur

        Aprime, vprime, eprime, etilde, vtilde, T = {}, {}, {}, {}, {}, {}
        mtilde = getMTilde(unrevealedAttrs)

        for issuer, credential in creds.items():
            Ra = integer(randomBits(LARGE_VPRIME))
            credDefPk = self.credDefPks[issuer]
            A, e, v = credential

            Aprime[issuer] = A * (credDefPk.S ** Ra) % credDefPk.N
            vprime[issuer] = (v - e * Ra)
            eprime[issuer] = e - (2 ** LARGE_E_START)

            etilde[issuer] = integer(randomBits(LARGE_ETILDE))
            vtilde[issuer] = integer(randomBits(LARGE_VTILDE))

            Rur = getRur(credDefPk, encodedAttrs[issuer], mtilde, unrevealedAttrs)

            T[issuer] = ((Aprime[issuer] ** etilde[issuer]) * Rur * (credDefPk.S ** vtilde[issuer])) % credDefPk.N

        tildValue = TildValue(mtilde, etilde, vtilde)
        primeValue = PrimeValue(Aprime, vprime, eprime)

        return SecretValue(tildValue, primeValue, T)

    # Why a dictionary of credentials is known as a presentationToken?
    # Source: https://cups.cs.cmu.edu/soups/2013/posters/soups13_posters-final24.pdf
    # In general, Privacy-ABCs (Privacy Attribute-Based Credentials) are issued just like ordinary
    # cryptographic credentials (e.g., X.509 credentials) using a digital (secret) signature key.
    # However, Privacy-ABCs allow their holder to transform them into a new token, called
    # presentation token, in such a way that the privacy of the user is protected

    def _getPresentationToken(self, creds: Dict[str, Credential]):
        credWithVPrime = {}
        for key, val in creds.items():
            A, e, vprimeprime = val
            v = vprimeprime + self._vprime[key]
            credWithVPrime[key] = Credential(A, e, v)
        return credWithVPrime


