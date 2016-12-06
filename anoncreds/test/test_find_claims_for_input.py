import pytest

from anoncreds.protocol.types import ProofInput, ProofClaims, PredicateGE


def testEmpty(prover1, allClaims):
    proofInput = ProofInput([], [])
    assert ({}, {}) == prover1._findClaims(proofInput)


def testOneRevealedOnly(prover1, allClaims, claimDefGvtId, attrRepo):
    proofInput = ProofInput(['name'])
    claimsGvt = prover1.wallet.getClaims(claimDefGvtId)
    proofClaims = {claimDefGvtId.claimDefKey:
                       ProofClaims(claimsGvt, ['name'], [])}
    revealedAttrs = {'name':
                         attrRepo.getAttributes(claimDefGvtId.claimDefKey, prover1.id).encoded()['name']}
    assert (proofClaims, revealedAttrs) == prover1._findClaims(proofInput)


def testPredicatesEmpty(prover1, allClaims, claimDefGvtId, attrRepo):
    proofInput = ProofInput(['name'], [])
    claimsGvt = prover1.wallet.getClaims(claimDefGvtId)
    proofClaims = {claimDefGvtId.claimDefKey:
                       ProofClaims(claimsGvt, ['name'], [])}
    revealedAttrs = {'name':
                         attrRepo.getAttributes(claimDefGvtId.claimDefKey, prover1.id).encoded()['name']}
    assert (proofClaims, revealedAttrs) == prover1._findClaims(proofInput)


def testOnePredicateOnly(prover1, allClaims, claimDefGvtId):
    proofInput = ProofInput(predicates=[PredicateGE('age', 18)])
    claimsGvt = prover1.wallet.getClaims(claimDefGvtId)
    proofClaims = {claimDefGvtId.claimDefKey:
                       ProofClaims(claimsGvt, [], [PredicateGE('age', 18)])}
    revealedAttrs = {}
    assert (proofClaims, revealedAttrs) == prover1._findClaims(proofInput)


def testRevealedEmpty(prover1, allClaims, claimDefGvtId):
    proofInput = ProofInput([], [PredicateGE('age', 18)])
    claimsGvt = prover1.wallet.getClaims(claimDefGvtId)
    proofClaims = {claimDefGvtId.claimDefKey:
                       ProofClaims(claimsGvt, [], [PredicateGE('age', 18)])}
    revealedAttrs = {}
    assert (proofClaims, revealedAttrs) == prover1._findClaims(proofInput)


def testRevealedAndPredicateSameIssuer(prover1, allClaims, claimDefGvtId, attrRepo):
    proofInput = ProofInput(['name'], [PredicateGE('age', 18)])
    claimsGvt = prover1.wallet.getClaims(claimDefGvtId)
    proofClaims = {claimDefGvtId.claimDefKey:
                       ProofClaims(claimsGvt, ['name'], [PredicateGE('age', 18)])}
    revealedAttrs = {'name':
                         attrRepo.getAttributes(claimDefGvtId.claimDefKey, prover1.id).encoded()['name']}
    assert (proofClaims, revealedAttrs) == prover1._findClaims(proofInput)


def testRevealedAndPredicateDifferentIssuers(prover1, allClaims, claimDefGvtId, claimDefXyzId, attrRepo):
    proofInput = ProofInput(['status'], [PredicateGE('age', 18)])
    claimsGvt = prover1.wallet.getClaims(claimDefGvtId)
    claimsXyz = prover1.wallet.getClaims(claimDefXyzId)
    proofClaims = {claimDefGvtId.claimDefKey:
                       ProofClaims(claimsGvt, [], [PredicateGE('age', 18)]),
                   claimDefXyzId.claimDefKey:
                       ProofClaims(claimsXyz, ['status'], [])}
    revealedAttrs = {'status':
                         attrRepo.getAttributes(claimDefXyzId.claimDefKey, prover1.id).encoded()['status']}
    assert (proofClaims, revealedAttrs) == prover1._findClaims(proofInput)


def testMultipledRevealed(prover1, allClaims, claimDefGvtId, claimDefXyzId, attrRepo):
    proofInput = ProofInput(['status', 'name'], [])
    claimsGvt = prover1.wallet.getClaims(claimDefGvtId)
    claimsXyz = prover1.wallet.getClaims(claimDefXyzId)
    proofClaims = {claimDefGvtId.claimDefKey:
                       ProofClaims(claimsGvt, ['name'], []),
                   claimDefXyzId.claimDefKey:
                       ProofClaims(claimsXyz, ['status'], [])}
    revealedAttrs = {'name':
                         attrRepo.getAttributes(claimDefGvtId.claimDefKey, prover1.id).encoded()['name'],
                     'status':
                         attrRepo.getAttributes(claimDefXyzId.claimDefKey, prover1.id).encoded()['status'],
                     }
    assert (proofClaims, revealedAttrs) == prover1._findClaims(proofInput)


def testMultipledPredicates(prover1, allClaims, claimDefGvtId, claimDefXyzId):
    proofInput = ProofInput([], [PredicateGE('age', 18), PredicateGE('period', 8)])
    claimsGvt = prover1.wallet.getClaims(claimDefGvtId)
    claimsXyz = prover1.wallet.getClaims(claimDefXyzId)
    proofClaims = {claimDefGvtId.claimDefKey:
                       ProofClaims(claimsGvt, [], [PredicateGE('age', 18)]),
                   claimDefXyzId.claimDefKey:
                       ProofClaims(claimsXyz, [], [PredicateGE('period', 8)])}
    revealedAttrs = {}
    assert (proofClaims, revealedAttrs) == prover1._findClaims(proofInput)


def testMultipleAll(prover1, allClaims, claimDefGvtId, claimDefXyzId, attrRepo):
    proofInput = ProofInput(['status', 'name'], [PredicateGE('age', 18), PredicateGE('period', 8)])
    claimsGvt = prover1.wallet.getClaims(claimDefGvtId)
    claimsXyz = prover1.wallet.getClaims(claimDefXyzId)
    proofClaims = {claimDefGvtId.claimDefKey:
                       ProofClaims(claimsGvt, ['name'], [PredicateGE('age', 18)]),
                   claimDefXyzId.claimDefKey:
                       ProofClaims(claimsXyz, ['status'], [PredicateGE('period', 8)])}
    revealedAttrs = {'name':
                         attrRepo.getAttributes(claimDefGvtId.claimDefKey, prover1.id).encoded()['name'],
                     'status':
                         attrRepo.getAttributes(claimDefXyzId.claimDefKey, prover1.id).encoded()['status'],
                     }
    assert (proofClaims, revealedAttrs) == prover1._findClaims(proofInput)


def testAttrNotFound(prover1, allClaims):
    proofInput = ProofInput(['name', 'aaaa'], [])
    with pytest.raises(ValueError):
        prover1._findClaims(proofInput)


def testPredicateNotFound(prover1, allClaims):
    proofInput = ProofInput([], [PredicateGE('age', 18), PredicateGE('aaaa', 8)])
    with pytest.raises(ValueError):
        prover1._findClaims(proofInput)
