from typing import Dict

from anoncreds.protocol.globals import LARGE_E_START, ITERATIONS, DELTA
from anoncreds.protocol.primary.primary_proof_common import calcTeq, calcTge
from anoncreds.protocol.types import PublicData, PrimaryEqualProof, \
    PrimaryPredicateGEProof, PrimaryProof, CredentialDefinition, PublicDataPrimary
from config.config import cmod


class PrimaryProofVerifier:
    def __init__(self, publicData: Dict[CredentialDefinition, PublicDataPrimary]):
        self._data = publicData

    def verify(self, credDef, cHash, primaryProof: PrimaryProof, allRevealedAttrs):
        cH = cmod.integer(cHash)
        THat = self._verifyEquality(credDef, cH, primaryProof.eqProof, allRevealedAttrs)
        for geProof in primaryProof.geProofs:
            THat += self._verifyGEPredicate(credDef, cH, geProof)

        return THat

    def _verifyEquality(self, credDef, cH, proof: PrimaryEqualProof, allRevealedAttrs):
        """
        Verify the proof
        :param attrs: The encoded attributes dictionary
        :param revealedAttrs: The revealed attributes list
        :param nonce: The nonce used to have a commit
        :return: A boolean with the verification status for the proof
        """
        THat = []
        pk = self._data[credDef].pk
        attrNames = self._data[credDef].credDef.attrNames
        unrevealedAttrNames = set(attrNames) - set(proof.revealedAttrNames)

        T1 = calcTeq(pk, proof.Aprime, proof.e, proof.v,
                     proof.m, proof.m1, proof.m2,
                     unrevealedAttrNames)

        Rar = 1 % pk.N
        for attrName in proof.revealedAttrNames:
            Rar *= pk.R[str(attrName)] ** allRevealedAttrs[attrName]
        Rar *= proof.Aprime ** (2 ** LARGE_E_START)
        T2 = (pk.Z / Rar) ** (-1 * cH) % pk.N
        T = T1 * T2 % pk.N

        THat.append(T)
        return THat

    def _verifyGEPredicate(self, credDef, cH, proof: PrimaryPredicateGEProof):
        pk = self._data[credDef].pk
        k, v = proof.predicate.attrName, proof.predicate.value

        TauList = calcTge(pk, proof.u, proof.r, proof.mj, proof.alpha, proof.T)

        for i in range(0, ITERATIONS):
            TT = proof.T[str(i)] ** (-1 * cH) % pk.N
            TauList[i] = TauList[i] * TT % pk.N
        TauList[ITERATIONS] = TauList[ITERATIONS] * ((proof.T[DELTA] * (pk.Z ** v)) ** (-1 * cH)) % pk.N
        TauList[ITERATIONS + 1] = (TauList[ITERATIONS + 1] * (proof.T[DELTA] ** (-1 * cH))) % pk.N

        return TauList
