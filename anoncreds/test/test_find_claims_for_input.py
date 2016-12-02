import pytest

from anoncreds.protocol.types import ProofInput, ProofClaims, PredicateGE


def testEmpty(prover1, allClaims):
    proofInput = ProofInput([], [])
    assert {} == prover1._findClaims(proofInput)

def testEmpty(prover1, allClaims):
    proofInput = ProofInput()
    assert {} == prover1._findClaims(proofInput)

def testOneRevealedOnly(prover1, allClaims, claimDefGvtId):
    proofInput = ProofInput(['name'])
    claimsGvt = prover1.wallet.getClaims(claimDefGvtId)
    assert {claimDefGvtId.claimDefKey:
                ProofClaims(claimsGvt, ['name'], [])} \
           == prover1._findClaims(proofInput)

def testPredicatesEmpty(prover1, allClaims, claimDefGvtId):
    proofInput = ProofInput(['name'], [])
    claimsGvt = prover1.wallet.getClaims(claimDefGvtId)
    assert {claimDefGvtId.claimDefKey:
                ProofClaims(claimsGvt, ['name'], [])} \
           == prover1._findClaims(proofInput)

def testOnePredicateOnly(prover1, allClaims, claimDefGvtId):
    proofInput = ProofInput(predicates=[PredicateGE('age', 18)])
    claimsGvt = prover1.wallet.getClaims(claimDefGvtId)
    assert {claimDefGvtId.claimDefKey:
                ProofClaims(claimsGvt, [], [PredicateGE('age', 18)])} \
           == prover1._findClaims(proofInput)

def testRevealedEmpty(prover1, allClaims, claimDefGvtId):
    proofInput = ProofInput([], [PredicateGE('age', 18)])
    claimsGvt = prover1.wallet.getClaims(claimDefGvtId)
    assert {claimDefGvtId.claimDefKey:
                ProofClaims(claimsGvt, [], [PredicateGE('age', 18)])} \
           == prover1._findClaims(proofInput)


def testRevealedAndPredicateSameIssuer(prover1, allClaims, claimDefGvtId):
    proofInput = ProofInput(['name'], [PredicateGE('age', 18)])
    claimsGvt = prover1.wallet.getClaims(claimDefGvtId)
    assert {claimDefGvtId.claimDefKey:
                ProofClaims(claimsGvt, ['name'], [PredicateGE('age', 18)])} \
           == prover1._findClaims(proofInput)


def testRevealedAndPredicateDifferentIssuers(prover1, allClaims, claimDefGvtId, claimDefXyzId):
    proofInput = ProofInput(['status'], [PredicateGE('age', 18)])
    claimsGvt = prover1.wallet.getClaims(claimDefGvtId)
    claimsXyz = prover1.wallet.getClaims(claimDefXyzId)
    assert {claimDefGvtId.claimDefKey:
                ProofClaims(claimsGvt, [], [PredicateGE('age', 18)]),
            claimDefXyzId.claimDefKey:
                ProofClaims(claimsXyz, ['status'], [])} \
           == prover1._findClaims(proofInput)


def testMultipledRevealed(prover1, allClaims, claimDefGvtId, claimDefXyzId):
    proofInput = ProofInput(['status', 'name'], [])
    claimsGvt = prover1.wallet.getClaims(claimDefGvtId)
    claimsXyz = prover1.wallet.getClaims(claimDefXyzId)
    assert {claimDefGvtId.claimDefKey:
                ProofClaims(claimsGvt, ['name'], []),
            claimDefXyzId.claimDefKey:
                ProofClaims(claimsXyz, ['status'], [])} \
           == prover1._findClaims(proofInput)


def testMultipledPredicates(prover1, allClaims, claimDefGvtId, claimDefXyzId):
    proofInput = ProofInput([], [PredicateGE('age', 18), PredicateGE('period', 8)])
    claimsGvt = prover1.wallet.getClaims(claimDefGvtId)
    claimsXyz = prover1.wallet.getClaims(claimDefXyzId)
    assert {claimDefGvtId.claimDefKey:
                ProofClaims(claimsGvt, [], [PredicateGE('age', 18)]),
            claimDefXyzId.claimDefKey:
                ProofClaims(claimsXyz, [], [PredicateGE('period', 8)])} \
           == prover1._findClaims(proofInput)


def testMultipleAll(prover1, allClaims, claimDefGvtId, claimDefXyzId):
    proofInput = ProofInput(['status', 'name'], [PredicateGE('age', 18), PredicateGE('period', 8)])
    claimsGvt = prover1.wallet.getClaims(claimDefGvtId)
    claimsXyz = prover1.wallet.getClaims(claimDefXyzId)
    assert {claimDefGvtId.claimDefKey:
                ProofClaims(claimsGvt, ['name'], [PredicateGE('age', 18)]),
            claimDefXyzId.claimDefKey:
                ProofClaims(claimsXyz, ['status'], [PredicateGE('period', 8)])} \
           == prover1._findClaims(proofInput)


def testAttrNotFound(prover1, allClaims):
    proofInput = ProofInput(['name', 'aaaa'], [])
    with pytest.raises(ValueError):
        prover1._findClaims(proofInput)


def testPredicateNotFound(prover1, allClaims):
    proofInput = ProofInput([], [PredicateGE('age', 18), PredicateGE('aaaa', 8)])
    with pytest.raises(ValueError):
        prover1._findClaims(proofInput)
