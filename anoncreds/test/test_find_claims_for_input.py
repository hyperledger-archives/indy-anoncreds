import pytest

from anoncreds.protocol.types import ProofInput, ProofClaims, PredicateGE
from anoncreds.test.conftest import issuerId1, issuerId2


def testEmpty(prover1, allClaimsProver1):
    proofInput = ProofInput([], [])
    assert {} == prover1.findClaims(allClaimsProver1, proofInput)


def testOneRevealedOnly(prover1, allClaimsProver1):
    proofInput = ProofInput(['name'], [])
    assert {issuerId1:
                ProofClaims(allClaimsProver1[issuerId1], ['name'], [])} \
           == prover1.findClaims(allClaimsProver1, proofInput)


def testOnePredicateOnly(prover1, allClaimsProver1):
    proofInput = ProofInput([], [PredicateGE('age', 18)])
    assert {issuerId1:
                ProofClaims(allClaimsProver1[issuerId1], [], [PredicateGE('age', 18)])} == \
           prover1.findClaims(allClaimsProver1, proofInput)


def testRevealedAndPredicateSameIssuer(prover1, allClaimsProver1):
    proofInput = ProofInput(['name'], [PredicateGE('age', 18)])
    assert {issuerId1:
                ProofClaims(allClaimsProver1[issuerId1], ['name'], [PredicateGE('age', 18)])} == \
           prover1.findClaims(allClaimsProver1, proofInput)


def testRevealedAndPredicateDifferentIssuers(prover1, allClaimsProver1):
    proofInput = ProofInput(['status'], [PredicateGE('age', 18)])
    assert {issuerId1:
                ProofClaims(allClaimsProver1[issuerId1], [], [PredicateGE('age', 18)]),
            issuerId2:
                ProofClaims(allClaimsProver1[issuerId2], ['status'], [])} == \
           prover1.findClaims(allClaimsProver1, proofInput)


def testMultipledRevealed(prover1, allClaimsProver1):
    proofInput = ProofInput(['status', 'name'], [])
    assert {issuerId1:
                ProofClaims(allClaimsProver1[issuerId1], ['name'], []),
            issuerId2:
                ProofClaims(allClaimsProver1[issuerId2], ['status'], [])} == \
           prover1.findClaims(allClaimsProver1, proofInput)


def testMultipledPredicates(prover1, allClaimsProver1):
    proofInput = ProofInput([], [PredicateGE('age', 18), PredicateGE('period', 8)])
    assert {issuerId1:
                ProofClaims(allClaimsProver1[issuerId1], [], [PredicateGE('age', 18)]),
            issuerId2:
                ProofClaims(allClaimsProver1[issuerId2], [], [PredicateGE('period', 8)])} == \
           prover1.findClaims(allClaimsProver1, proofInput)


def testMultipleAll(prover1, allClaimsProver1):
    proofInput = ProofInput(['status', 'name'], [PredicateGE('age', 18), PredicateGE('period', 8)])
    assert {issuerId1:
                ProofClaims(allClaimsProver1[issuerId1], ['name'], [PredicateGE('age', 18)]),
            issuerId2:
                ProofClaims(allClaimsProver1[issuerId2], ['status'], [PredicateGE('period', 8)])} == \
           prover1.findClaims(allClaimsProver1, proofInput)


def testAttrNotFound(prover1, allClaimsProver1):
    proofInput = ProofInput(['name', 'aaaa'], [])
    with pytest.raises(ValueError):
        prover1.findClaims(allClaimsProver1, proofInput)


def testPredicateNotFound(prover1, allClaimsProver1):
    proofInput = ProofInput([], [PredicateGE('age', 18), PredicateGE('aaaa', 8)])
    with pytest.raises(ValueError):
        prover1.findClaims(allClaimsProver1, proofInput)
