import pytest

from anoncreds.protocol.types import ProofRequest, ProofClaims, PredicateGE, RequestedProof, AttributeInfo
from anoncreds.protocol.utils import encodeAttr


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testEmpty(prover1):
    proofRequest = ProofRequest("proof1", "1.0", 1, verifiableAttributes={}, predicates={})
    assert ({}, RequestedProof([], [], [], [])) == await prover1._findClaims(proofRequest)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testOneRevealedOnly(prover1, allClaims, schemaGvtId, attrRepo, schemaGvt):
    proofRequest = ProofRequest("proof1", "1.0", 1, verifiableAttributes={'uuid': AttributeInfo(name='name')})
    claimsGvt = await prover1.wallet.getClaimSignature(schemaGvtId)

    proofClaims = {schemaGvt.seqId: ProofClaims(claimsGvt, ['name'], [])}
    attr = attrRepo.getAttributes(schemaGvtId.schemaKey, prover1.proverId)['name']
    requestedProof = RequestedProof(revealed_attrs={'uuid': [str(schemaGvt.seqId), attr, str(encodeAttr(attr))]})

    assert proofClaims, requestedProof == await prover1._findClaims(proofRequest)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testPredicatesEmpty(prover1, allClaims, schemaGvtId, attrRepo, schemaGvt):
    proofRequest = ProofRequest("proof1", "1.0", 1,
                                verifiableAttributes={'uuid': AttributeInfo(name='name')}, predicates={})

    claimsGvt = await prover1.wallet.getClaimSignature(schemaGvtId)

    proofClaims = {schemaGvt.seqId: ProofClaims(claimsGvt, ['name'], [])}

    attr = attrRepo.getAttributes(schemaGvtId.schemaKey, prover1.proverId)['name']
    requestedProof = RequestedProof(revealed_attrs={'uuid': [schemaGvt.seqId, attr, str(encodeAttr(attr))]})

    assert proofClaims, requestedProof == await prover1._findClaims(proofRequest)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testOnePredicateOnly(prover1, allClaims, schemaGvtId, schemaGvt):
    proofRequest = ProofRequest("proof1", "1.0", 1, predicates={'uuid': PredicateGE('age', 18)})

    claimsGvt = await prover1.wallet.getClaimSignature(schemaGvtId)
    proofClaims = {schemaGvt.seqId:
                       ProofClaims(claimsGvt, [], [PredicateGE('age', 18)])}

    requestedProof = RequestedProof(predicates={'uuid': schemaGvt.seqId})

    assert proofClaims, requestedProof == await prover1._findClaims(proofRequest)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testRevealedEmpty(prover1, allClaims, schemaGvtId, schemaGvt):
    proofRequest = ProofRequest("proof1", "1.0", 1,
                                verifiableAttributes={}, predicates={'uuid': PredicateGE('age', 18)})

    claimsGvt = await prover1.wallet.getClaimSignature(schemaGvtId)
    proofClaims = {schemaGvt.seqId:
                       ProofClaims(claimsGvt, [], [PredicateGE('age', 18)])}

    requestedProof = RequestedProof(predicates={'uuid': schemaGvt.seqId})

    assert proofClaims, requestedProof == await prover1._findClaims(proofRequest)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testRevealedAndPredicateSameIssuer(prover1, allClaims, schemaGvtId,
                                             attrRepo, schemaGvt):
    proofRequest = ProofRequest("proof1", "1.0", 1,
                                verifiableAttributes={'attr_uuid': AttributeInfo(name='name')},
                                predicates={'predicate_uuid': PredicateGE('age', 18)})

    claimsGvt = await prover1.wallet.getClaimSignature(schemaGvtId)
    proofClaims = {schemaGvt.seqId: ProofClaims(claimsGvt, ['name'], [PredicateGE('age', 18)])}

    attr = attrRepo.getAttributes(schemaGvtId.schemaKey, prover1.proverId)['name']
    requestedProof = RequestedProof(revealed_attrs={'attr_uuid': [schemaGvt.seqId, attr, str(encodeAttr(attr))]},
                                    predicates={'predicate_uuid': schemaGvt.seqId})

    assert proofClaims, requestedProof == await prover1._findClaims(proofRequest)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testRevealedAndPredicateDifferentIssuers(prover1, allClaims,
                                                   schemaGvtId, schemaXyzId,
                                                   attrRepo, schemaGvt):
    proofRequest = ProofRequest("proof1", "1.0", 1,
                                verifiableAttributes={'attr_uuid': AttributeInfo(name='status')},
                                predicates={'predicate_uuid': PredicateGE('age', 18)})

    claimsGvt = await prover1.wallet.getClaimSignature(schemaGvtId)
    claimsXyz = await prover1.wallet.getClaimSignature(schemaXyzId)
    proofClaims = {schemaGvt.seqId: ProofClaims(claimsGvt, [], [PredicateGE('age', 18)]),
                   schemaGvt.seqId: ProofClaims(claimsXyz, ['status'], [])}

    attr = attrRepo.getAttributes(schemaXyzId.schemaKey, prover1.proverId)['status']
    requestedProof = RequestedProof(revealed_attrs={'attr_uuid': [schemaGvt.seqId, attr, str(encodeAttr(attr))]},
                                    predicates={'predicate_uuid': schemaGvt.seqId})

    assert proofClaims, requestedProof == await prover1._findClaims(proofRequest)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipledRevealed(prover1, allClaims, schemaGvtId,
                                schemaXyzId, attrRepo, schemaGvt):
    proofRequest = ProofRequest("proof1", "1.0", 1,
                                verifiableAttributes={'attr_uuid1': AttributeInfo(name='status'),
                                                      'attr_uuid2': AttributeInfo(name='name')})

    claimsGvt = await prover1.wallet.getClaimSignature(schemaGvtId)
    claimsXyz = await prover1.wallet.getClaimSignature(schemaXyzId)
    proofClaims = {schemaGvt.seqId: ProofClaims(claimsGvt, ['name'], []),
                   schemaGvt.seqId: ProofClaims(claimsXyz, ['status'], [])}

    attr1 = attrRepo.getAttributes(schemaXyzId.schemaKey, prover1.proverId)['status']
    attr2 = attrRepo.getAttributes(schemaGvtId.schemaKey, prover1.proverId)['name']
    requestedProof = RequestedProof(revealed_attrs={'attr_uuid1': [schemaGvt.seqId, attr1, str(encodeAttr(attr1))],
                                                    'attr_uuid2': [schemaGvt.seqId, attr2, str(encodeAttr(attr2))]})

    assert proofClaims, requestedProof == await prover1._findClaims(proofRequest)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipledPredicates(prover1, allClaims, schemaGvtId,
                                  schemaXyzId, schemaGvt):
    proofRequest = ProofRequest("proof1", "1.0", 1,
                                predicates={'predicate_uuid1': PredicateGE('age', 18),
                                            'predicate_uuid2': PredicateGE('period', 8)})

    claimsGvt = await prover1.wallet.getClaimSignature(schemaGvtId)
    claimsXyz = await prover1.wallet.getClaimSignature(schemaXyzId)
    proofClaims = {schemaGvt.seqId: ProofClaims(claimsGvt, [], [PredicateGE('age', 18)]),
                   schemaGvt.seqId: ProofClaims(claimsXyz, [], [PredicateGE('period', 8)])}

    requestedProof = RequestedProof(predicates={'predicate_uuid1': schemaGvt.seqId,
                                                'predicate_uuid2': schemaGvt.seqId})

    assert proofClaims, requestedProof == await prover1._findClaims(proofRequest)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipleAll(prover1, allClaims, schemaGvtId, schemaXyzId,
                          attrRepo, schemaGvt):
    proofRequest = ProofRequest("proof1", "1.0", 1,
                                verifiableAttributes={'attr_uuid1': AttributeInfo(name='status'),
                                                      'attr_uuid2': AttributeInfo(name='name')},
                                predicates={'predicate_uuid1': PredicateGE('age', 18),
                                            'predicate_uuid2': PredicateGE('period', 8)})

    claimsGvt = await prover1.wallet.getClaimSignature(schemaGvtId)
    claimsXyz = await prover1.wallet.getClaimSignature(schemaXyzId)
    proofClaims = {schemaGvt.seqId: ProofClaims(claimsGvt, ['name'], [PredicateGE('age', 18)]),
                   schemaGvt.seqId: ProofClaims(claimsXyz, ['status'], [PredicateGE('period', 8)])}

    attr1 = attrRepo.getAttributes(schemaXyzId.schemaKey, prover1.proverId)['status']
    attr2 = attrRepo.getAttributes(schemaGvtId.schemaKey, prover1.proverId)['name']

    requestedProof = RequestedProof(
        revealed_attrs={'attr_uuid1': [schemaGvt.seqId, attr1, str(encodeAttr(attr1))],
                        'attr_uuid2': [schemaGvt.seqId, attr2, str(encodeAttr(attr2))]},
        predicates={'predicate_uuid1': schemaGvt.seqId,
                    'predicate_uuid2': schemaGvt.seqId})

    assert proofClaims, requestedProof == await prover1._findClaims(proofRequest)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testAttrNotFound(prover1, allClaims):
    proofRequest = ProofRequest("proof1", "1.0", 1,
                                verifiableAttributes={'attr_uuid1': AttributeInfo(name='name'),
                                                      'attr_uuid2': AttributeInfo(name='aaa')})
    with pytest.raises(ValueError):
        await prover1._findClaims(proofRequest)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testPredicateNotFound(prover1, allClaims):
    proofRequest = ProofRequest("proof1", "1.0", 1,
                                predicates={'predicate_uuid1': PredicateGE('age', 18),
                                            'predicate_uuid2': PredicateGE('aaaa', 8)})
    with pytest.raises(ValueError):
        await prover1._findClaims(proofRequest)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testOneRevealedFromSchema(prover1, allClaims, schemaGvtId, attrRepo, schemaGvt):
    proofRequest = ProofRequest("proof1", "1.0", 1,
                                verifiableAttributes={
                                    'uuid': AttributeInfo(name='name', schema_seq_no=schemaGvt.seqId)})
    claimsGvt = await prover1.wallet.getClaimSignature(schemaGvtId)

    proofClaims = {schemaGvt.seqId: ProofClaims(claimsGvt, ['name'], [])}
    attr = attrRepo.getAttributes(schemaGvtId.schemaKey, prover1.proverId)['name']
    requestedProof = RequestedProof(revealed_attrs={'uuid': [str(schemaGvt.seqId), attr, str(encodeAttr(attr))]})

    assert proofClaims, requestedProof == await prover1._findClaims(proofRequest)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testOneRevealedFromOtherSchema(prover1, allClaims, schemaXyz):
    proofRequest = ProofRequest("proof1", "1.0", 1,
                                verifiableAttributes={
                                    'uuid': AttributeInfo(name='name', schema_seq_no=schemaXyz.seqId)})

    with pytest.raises(ValueError):
        await prover1._findClaims(proofRequest)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testOneRevealedFromSpecificSchemaAndIssuer(prover1, allClaims, schemaGvt, schemaGvtId, attrRepo, keysGvt):
    proofRequest = ProofRequest("proof1", "1.0", 1,
                                verifiableAttributes={'uuid': AttributeInfo(name='name', schema_seq_no=schemaGvt.seqId,
                                                                            issuer_did=schemaGvt.issuerId)})
    claimsGvt = await prover1.wallet.getClaimSignature(schemaGvtId)

    proofClaims = {schemaGvt.seqId: ProofClaims(claimsGvt, ['name'], [])}
    attr = attrRepo.getAttributes(schemaGvtId.schemaKey, prover1.proverId)['name']
    requestedProof = RequestedProof(revealed_attrs={'uuid': [str(schemaGvt.seqId), attr, str(encodeAttr(attr))]})

    assert proofClaims, requestedProof == await prover1._findClaims(proofRequest)

    assert proofClaims, requestedProof == await prover1._findClaims(proofRequest)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testOneRevealedFromOtherIssuer(prover1, allClaims, schemaGvt, schemaXyz):
    proofRequest = ProofRequest("proof1", "1.0", 1,
                                verifiableAttributes={'uuid': AttributeInfo(name='name', schema_seq_no=schemaGvt.seqId,
                                                                            issuer_did=schemaXyz.issuerId)})

    with pytest.raises(ValueError):
        await prover1._findClaims(proofRequest)
