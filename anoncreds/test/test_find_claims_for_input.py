import pytest

from anoncreds.protocol.types import ProofInput, ProofClaims, PredicateGE


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testEmpty(prover1, allClaims):
    proofInput = ProofInput([], [])
    assert ({}, {}) == await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testOneRevealedOnly(prover1, allClaims, claimDefGvtId, attrRepo):
    proofInput = ProofInput(['name'])
    claimsGvt = await prover1.wallet.getClaims(claimDefGvtId)
    proofClaims = {claimDefGvtId.claimDefKey:
                       ProofClaims(claimsGvt, ['name'], [])}
    revealedAttrs = {'name':
                         attrRepo.getAttributes(claimDefGvtId.claimDefKey,
                                                prover1.proverId).encoded()[
                             'name']}
    assert (proofClaims, revealedAttrs) == await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testPredicatesEmpty(prover1, allClaims, claimDefGvtId, attrRepo):
    proofInput = ProofInput(['name'], [])
    claimsGvt = await prover1.wallet.getClaims(claimDefGvtId)
    proofClaims = {claimDefGvtId.claimDefKey:
                       ProofClaims(claimsGvt, ['name'], [])}
    revealedAttrs = {'name':
                         attrRepo.getAttributes(claimDefGvtId.claimDefKey,
                                                prover1.proverId).encoded()[
                             'name']}
    assert (proofClaims, revealedAttrs) == await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testOnePredicateOnly(prover1, allClaims, claimDefGvtId):
    proofInput = ProofInput(predicates=[PredicateGE('age', 18)])
    claimsGvt = await prover1.wallet.getClaims(claimDefGvtId)
    proofClaims = {claimDefGvtId.claimDefKey:
                       ProofClaims(claimsGvt, [], [PredicateGE('age', 18)])}
    revealedAttrs = {}
    assert (proofClaims, revealedAttrs) == await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testRevealedEmpty(prover1, allClaims, claimDefGvtId):
    proofInput = ProofInput([], [PredicateGE('age', 18)])
    claimsGvt = await prover1.wallet.getClaims(claimDefGvtId)
    proofClaims = {claimDefGvtId.claimDefKey:
                       ProofClaims(claimsGvt, [], [PredicateGE('age', 18)])}
    revealedAttrs = {}
    assert (proofClaims, revealedAttrs) == await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testRevealedAndPredicateSameIssuer(prover1, allClaims, claimDefGvtId,
                                             attrRepo):
    proofInput = ProofInput(['name'], [PredicateGE('age', 18)])
    claimsGvt = await prover1.wallet.getClaims(claimDefGvtId)
    proofClaims = {claimDefGvtId.claimDefKey:
                       ProofClaims(claimsGvt, ['name'],
                                   [PredicateGE('age', 18)])}
    revealedAttrs = {'name':
                         attrRepo.getAttributes(claimDefGvtId.claimDefKey,
                                                prover1.proverId).encoded()[
                             'name']}
    assert (proofClaims, revealedAttrs) == await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testRevealedAndPredicateDifferentIssuers(prover1, allClaims,
                                                   claimDefGvtId, claimDefXyzId,
                                                   attrRepo):
    proofInput = ProofInput(['status'], [PredicateGE('age', 18)])
    claimsGvt = await prover1.wallet.getClaims(claimDefGvtId)
    claimsXyz = await prover1.wallet.getClaims(claimDefXyzId)
    proofClaims = {claimDefGvtId.claimDefKey:
                       ProofClaims(claimsGvt, [], [PredicateGE('age', 18)]),
                   claimDefXyzId.claimDefKey:
                       ProofClaims(claimsXyz, ['status'], [])}
    revealedAttrs = {'status':
                         attrRepo.getAttributes(claimDefXyzId.claimDefKey,
                                                prover1.proverId).encoded()[
                             'status']}
    assert (proofClaims, revealedAttrs) == await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipledRevealed(prover1, allClaims, claimDefGvtId,
                                claimDefXyzId, attrRepo):
    proofInput = ProofInput(['status', 'name'], [])
    claimsGvt = await prover1.wallet.getClaims(claimDefGvtId)
    claimsXyz = await prover1.wallet.getClaims(claimDefXyzId)
    proofClaims = {claimDefGvtId.claimDefKey:
                       ProofClaims(claimsGvt, ['name'], []),
                   claimDefXyzId.claimDefKey:
                       ProofClaims(claimsXyz, ['status'], [])}
    revealedAttrs = {'name':
                         attrRepo.getAttributes(claimDefGvtId.claimDefKey,
                                                prover1.proverId).encoded()[
                             'name'],
                     'status':
                         attrRepo.getAttributes(claimDefXyzId.claimDefKey,
                                                prover1.proverId).encoded()[
                             'status'],
                     }
    assert (proofClaims, revealedAttrs) == await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipledPredicates(prover1, allClaims, claimDefGvtId,
                                  claimDefXyzId):
    proofInput = ProofInput([],
                            [PredicateGE('age', 18), PredicateGE('period', 8)])
    claimsGvt = await prover1.wallet.getClaims(claimDefGvtId)
    claimsXyz = await prover1.wallet.getClaims(claimDefXyzId)
    proofClaims = {claimDefGvtId.claimDefKey:
                       ProofClaims(claimsGvt, [], [PredicateGE('age', 18)]),
                   claimDefXyzId.claimDefKey:
                       ProofClaims(claimsXyz, [], [PredicateGE('period', 8)])}
    revealedAttrs = {}
    assert (proofClaims, revealedAttrs) == await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipleAll(prover1, allClaims, claimDefGvtId, claimDefXyzId,
                          attrRepo):
    proofInput = ProofInput(['status', 'name'],
                            [PredicateGE('age', 18), PredicateGE('period', 8)])
    claimsGvt = await prover1.wallet.getClaims(claimDefGvtId)
    claimsXyz = await prover1.wallet.getClaims(claimDefXyzId)
    proofClaims = {claimDefGvtId.claimDefKey:
                       ProofClaims(claimsGvt, ['name'],
                                   [PredicateGE('age', 18)]),
                   claimDefXyzId.claimDefKey:
                       ProofClaims(claimsXyz, ['status'],
                                   [PredicateGE('period', 8)])}
    revealedAttrs = {'name':
                         attrRepo.getAttributes(claimDefGvtId.claimDefKey,
                                                prover1.proverId).encoded()[
                             'name'],
                     'status':
                         attrRepo.getAttributes(claimDefXyzId.claimDefKey,
                                                prover1.proverId).encoded()[
                             'status'],
                     }
    assert (proofClaims, revealedAttrs) == await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testAttrNotFound(prover1, allClaims):
    proofInput = ProofInput(['name', 'aaaa'], [])
    with pytest.raises(ValueError):
        await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testPredicateNotFound(prover1, allClaims):
    proofInput = ProofInput([],
                            [PredicateGE('age', 18), PredicateGE('aaaa', 8)])
    with pytest.raises(ValueError):
        await prover1._findClaims(proofInput)
