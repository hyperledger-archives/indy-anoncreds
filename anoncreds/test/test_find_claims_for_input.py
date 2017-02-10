import pytest

from anoncreds.protocol.types import ProofInput, ProofClaims, PredicateGE


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testEmpty(prover1, allClaims):
    proofInput = ProofInput([], [])
    assert ({}, {}) == await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testOneRevealedOnly(prover1, allClaims, schemaGvtId, attrRepo):
    proofInput = ProofInput(['name'])
    claimsGvt = await prover1.wallet.getClaims(schemaGvtId)
    proofClaims = {schemaGvtId.schemaKey:
                       ProofClaims(claimsGvt, ['name'], [])}
    revealedAttrs = {'name':
                         attrRepo.getAttributes(schemaGvtId.schemaKey,
                                                prover1.proverId).encoded()[
                             'name']}
    assert (proofClaims, revealedAttrs) == await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testPredicatesEmpty(prover1, allClaims, schemaGvtId, attrRepo):
    proofInput = ProofInput(['name'], [])
    claimsGvt = await prover1.wallet.getClaims(schemaGvtId)
    proofClaims = {schemaGvtId.schemaKey:
                       ProofClaims(claimsGvt, ['name'], [])}
    revealedAttrs = {'name':
                         attrRepo.getAttributes(schemaGvtId.schemaKey,
                                                prover1.proverId).encoded()[
                             'name']}
    assert (proofClaims, revealedAttrs) == await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testOnePredicateOnly(prover1, allClaims, schemaGvtId):
    proofInput = ProofInput(predicates=[PredicateGE('age', 18)])
    claimsGvt = await prover1.wallet.getClaims(schemaGvtId)
    proofClaims = {schemaGvtId.schemaKey:
                       ProofClaims(claimsGvt, [], [PredicateGE('age', 18)])}
    revealedAttrs = {}
    assert (proofClaims, revealedAttrs) == await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testRevealedEmpty(prover1, allClaims, schemaGvtId):
    proofInput = ProofInput([], [PredicateGE('age', 18)])
    claimsGvt = await prover1.wallet.getClaims(schemaGvtId)
    proofClaims = {schemaGvtId.schemaKey:
                       ProofClaims(claimsGvt, [], [PredicateGE('age', 18)])}
    revealedAttrs = {}
    assert (proofClaims, revealedAttrs) == await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testRevealedAndPredicateSameIssuer(prover1, allClaims, schemaGvtId,
                                             attrRepo):
    proofInput = ProofInput(['name'], [PredicateGE('age', 18)])
    claimsGvt = await prover1.wallet.getClaims(schemaGvtId)
    proofClaims = {schemaGvtId.schemaKey:
                       ProofClaims(claimsGvt, ['name'],
                                   [PredicateGE('age', 18)])}
    revealedAttrs = {'name':
                         attrRepo.getAttributes(schemaGvtId.schemaKey,
                                                prover1.proverId).encoded()[
                             'name']}
    assert (proofClaims, revealedAttrs) == await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testRevealedAndPredicateDifferentIssuers(prover1, allClaims,
                                                   schemaGvtId, schemaXyzId,
                                                   attrRepo):
    proofInput = ProofInput(['status'], [PredicateGE('age', 18)])
    claimsGvt = await prover1.wallet.getClaims(schemaGvtId)
    claimsXyz = await prover1.wallet.getClaims(schemaXyzId)
    proofClaims = {schemaGvtId.schemaKey:
                       ProofClaims(claimsGvt, [], [PredicateGE('age', 18)]),
                   schemaXyzId.schemaKey:
                       ProofClaims(claimsXyz, ['status'], [])}
    revealedAttrs = {'status':
                         attrRepo.getAttributes(schemaXyzId.schemaKey,
                                                prover1.proverId).encoded()[
                             'status']}
    assert (proofClaims, revealedAttrs) == await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipledRevealed(prover1, allClaims, schemaGvtId,
                                schemaXyzId, attrRepo):
    proofInput = ProofInput(['status', 'name'], [])
    claimsGvt = await prover1.wallet.getClaims(schemaGvtId)
    claimsXyz = await prover1.wallet.getClaims(schemaXyzId)
    proofClaims = {schemaGvtId.schemaKey:
                       ProofClaims(claimsGvt, ['name'], []),
                   schemaXyzId.schemaKey:
                       ProofClaims(claimsXyz, ['status'], [])}
    revealedAttrs = {'name':
                         attrRepo.getAttributes(schemaGvtId.schemaKey,
                                                prover1.proverId).encoded()[
                             'name'],
                     'status':
                         attrRepo.getAttributes(schemaXyzId.schemaKey,
                                                prover1.proverId).encoded()[
                             'status'],
                     }
    assert (proofClaims, revealedAttrs) == await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipledPredicates(prover1, allClaims, schemaGvtId,
                                  schemaXyzId):
    proofInput = ProofInput([],
                            [PredicateGE('age', 18), PredicateGE('period', 8)])
    claimsGvt = await prover1.wallet.getClaims(schemaGvtId)
    claimsXyz = await prover1.wallet.getClaims(schemaXyzId)
    proofClaims = {schemaGvtId.schemaKey:
                       ProofClaims(claimsGvt, [], [PredicateGE('age', 18)]),
                   schemaXyzId.schemaKey:
                       ProofClaims(claimsXyz, [], [PredicateGE('period', 8)])}
    revealedAttrs = {}
    assert (proofClaims, revealedAttrs) == await prover1._findClaims(proofInput)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipleAll(prover1, allClaims, schemaGvtId, schemaXyzId,
                          attrRepo):
    proofInput = ProofInput(['status', 'name'],
                            [PredicateGE('age', 18), PredicateGE('period', 8)])
    claimsGvt = await prover1.wallet.getClaims(schemaGvtId)
    claimsXyz = await prover1.wallet.getClaims(schemaXyzId)
    proofClaims = {schemaGvtId.schemaKey:
                       ProofClaims(claimsGvt, ['name'],
                                   [PredicateGE('age', 18)]),
                   schemaXyzId.schemaKey:
                       ProofClaims(claimsXyz, ['status'],
                                   [PredicateGE('period', 8)])}
    revealedAttrs = {'name':
                         attrRepo.getAttributes(schemaGvtId.schemaKey,
                                                prover1.proverId).encoded()[
                             'name'],
                     'status':
                         attrRepo.getAttributes(schemaXyzId.schemaKey,
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
