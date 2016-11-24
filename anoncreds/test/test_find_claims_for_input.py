import pytest

from anoncreds.protocol.types import ProofInput, ProofClaims, PredicateGE


def testEmpty(prover1, allClaimsProver1):
    proofInput = ProofInput([], [])
    assert {} == prover1._findClaims(proofInput)


def testOneRevealedOnly(prover1, allClaimsProver1, credDefGvt):
    proofInput = ProofInput(['name'], [])
    assert {credDefGvt:
                ProofClaims(allClaimsProver1[credDefGvt], ['name'], [])} \
           == prover1.findClaims(allClaimsProver1, proofInput)


def testOnePredicateOnly(prover1, allClaimsProver1, credDefGvt):
    proofInput = ProofInput([], [PredicateGE('age', 18)])
    assert {credDefGvt:
                ProofClaims(allClaimsProver1[credDefGvt], [], [PredicateGE('age', 18)])} == \
           prover1.findClaims(allClaimsProver1, proofInput)


def testRevealedAndPredicateSameIssuer(prover1, allClaimsProver1, credDefGvt):
    proofInput = ProofInput(['name'], [PredicateGE('age', 18)])
    assert {credDefGvt:
                ProofClaims(allClaimsProver1[credDefGvt], ['name'], [PredicateGE('age', 18)])} == \
           prover1.findClaims(allClaimsProver1, proofInput)


def testRevealedAndPredicateDifferentIssuers(prover1, allClaimsProver1, credDefGvt, credDefXyz):
    proofInput = ProofInput(['status'], [PredicateGE('age', 18)])
    assert {credDefGvt:
                ProofClaims(allClaimsProver1[credDefGvt], [], [PredicateGE('age', 18)]),
            credDefXyz:
                ProofClaims(allClaimsProver1[credDefXyz], ['status'], [])} == \
           prover1.findClaims(allClaimsProver1, proofInput)


def testMultipledRevealed(prover1, allClaimsProver1, credDefGvt, credDefXyz):
    proofInput = ProofInput(['status', 'name'], [])
    assert {credDefGvt:
                ProofClaims(allClaimsProver1[credDefGvt], ['name'], []),
            credDefXyz:
                ProofClaims(allClaimsProver1[credDefXyz], ['status'], [])} == \
           prover1.findClaims(allClaimsProver1, proofInput)


def testMultipledPredicates(prover1, allClaimsProver1, credDefGvt, credDefXyz):
    proofInput = ProofInput([], [PredicateGE('age', 18), PredicateGE('period', 8)])
    assert {credDefGvt:
                ProofClaims(allClaimsProver1[credDefGvt], [], [PredicateGE('age', 18)]),
            credDefXyz:
                ProofClaims(allClaimsProver1[credDefXyz], [], [PredicateGE('period', 8)])} == \
           prover1.findClaims(allClaimsProver1, proofInput)


def testMultipleAll(prover1, allClaimsProver1, credDefGvt, credDefXyz):
    proofInput = ProofInput(['status', 'name'], [PredicateGE('age', 18), PredicateGE('period', 8)])
    assert {credDefGvt:
                ProofClaims(allClaimsProver1[credDefGvt], ['name'], [PredicateGE('age', 18)]),
            credDefXyz:
                ProofClaims(allClaimsProver1[credDefXyz], ['status'], [PredicateGE('period', 8)])} == \
           prover1.findClaims(allClaimsProver1, proofInput)


def testAttrNotFound(prover1, allClaimsProver1):
    proofInput = ProofInput(['name', 'aaaa'], [])
    with pytest.raises(ValueError):
        prover1.findClaims(allClaimsProver1, proofInput)


def testPredicateNotFound(prover1, allClaimsProver1):
    proofInput = ProofInput([], [PredicateGE('age', 18), PredicateGE('aaaa', 8)])
    with pytest.raises(ValueError):
        prover1.findClaims(allClaimsProver1, proofInput)
