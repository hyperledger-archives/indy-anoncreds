import pytest

from anoncreds.protocol.types import ProofRequest, PredicateGE, Claims, \
    ProofClaims, AttributeInfo
from anoncreds.test.conftest import presentProofAndVerify


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testPrimaryClaimOnlyEmpty(prover1, verifier, claimsProver1Gvt, nonce):
    proofRequest = ProofRequest("proof1", "1.0", nonce)
    claims, requestedProof = await prover1._findClaims(proofRequest)
    claims = {schemaId: ProofClaims(
        Claims(primaryClaim=proofClaim.claims.primaryClaim))
              for schemaId, proofClaim in claims.items()}

    proof = await prover1._prepareProof(claims, proofRequest.nonce, requestedProof)

    assert await verifier.verify(proofRequest, proof)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testPrimaryClaimNoPredicates(prover1, verifier, claimsProver1Gvt,
                                       nonce, schemaGvtId):
    proofRequest = ProofRequest("proof1", "1.0", nonce,
                                verifiableAttributes={'uuid1': AttributeInfo(name='name')}, predicates={})

    claims, requestedProof = await prover1._findClaims(proofRequest)
    claims = {
        schemaId: ProofClaims(
            Claims(primaryClaim=proofClaim.claims.primaryClaim), [AttributeInfo(name='name')], [])
        for schemaId, proofClaim in claims.items()}
    proof = await prover1._prepareProof(claims, proofRequest.nonce, requestedProof)

    assert await verifier.verify(proofRequest, proof)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testPrimaryClaimPredicatesOnly(prover1, verifier, claimsProver1Gvt,
                                         nonce, schemaGvtId):
    predicate = PredicateGE('age', 18)
    proofRequest = ProofRequest("proof1", "1.0", nonce,
                                verifiableAttributes={},
                                predicates={'predicate_uuid1': predicate})

    claims, requestedProof = await prover1._findClaims(proofRequest)
    claims = {
        schemaId: ProofClaims(
            Claims(primaryClaim=proofClaim.claims.primaryClaim), predicates=[predicate])
        for schemaId, proofClaim in claims.items()}

    proof = await prover1._prepareProof(claims, proofRequest.nonce, requestedProof)

    assert await verifier.verify(proofRequest, proof)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testEmpty(prover1, verifier, claimsProver1Gvt):
    assert await presentProofAndVerify(verifier, ProofRequest("proof1", "1.0", verifier.generateNonce()), prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testNoPredicates(prover1, verifier, claimsProver1Gvt):
    proofRequest = ProofRequest("proof1", "1.0", verifier.generateNonce(),
                                verifiableAttributes={'uuid': AttributeInfo(name='name')}, predicates={})
    assert await presentProofAndVerify(verifier, proofRequest, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipleRevealedAttrs(prover1, verifier, claimsProver1Gvt):
    proofRequest = ProofRequest("proof1", "1.0", verifier.generateNonce(),
                                verifiableAttributes={'uuid1': AttributeInfo(name='name'),
                                                      'uuid2': AttributeInfo(name='sex')},
                                predicates={})
    assert await presentProofAndVerify(verifier, proofRequest, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testGePredicate(prover1, verifier, claimsProver1Gvt):
    proofRequest = ProofRequest("proof1", "1.0", verifier.generateNonce(),
                                verifiableAttributes={'attr_uuid': AttributeInfo(name='name')},
                                predicates={'predicate_uuid': PredicateGE('age', 18)})
    assert await presentProofAndVerify(verifier, proofRequest, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testGePredicateForEqual(prover1, verifier, claimsProver1Gvt):
    proofRequest = ProofRequest("proof1", "1.0", verifier.generateNonce(),
                                verifiableAttributes={'attr_uuid': AttributeInfo(name='name')},
                                predicates={'predicate_uuid': PredicateGE('age', 28)})
    assert await presentProofAndVerify(verifier, proofRequest, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testGePredicateNegative(prover1, verifier, claimsProver1Gvt):
    proofRequest = ProofRequest("proof1", "1.0", verifier.generateNonce(),
                                verifiableAttributes={'attr_uuid': AttributeInfo(name='name')},
                                predicates={'predicate_uuid': PredicateGE('age', 29)})
    with pytest.raises(ValueError):
        await presentProofAndVerify(verifier, proofRequest, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipleGePredicate(prover1, verifier, claimsProver1Gvt):
    proofRequest = ProofRequest("proof1", "1.0", verifier.generateNonce(),
                                verifiableAttributes={'attr_uuid': AttributeInfo(name='name')},
                                predicates={'predicate_uuid1': PredicateGE('age', 18),
                                            'predicate_uuid2': PredicateGE('height', 170)})
    assert await presentProofAndVerify(verifier, proofRequest, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipleGePredicateNegative(prover1, verifier, claimsProver1Gvt):
    proofRequest = ProofRequest("proof1", "1.0", verifier.generateNonce(),
                                verifiableAttributes={'attr_uuid': AttributeInfo(name='name')},
                                predicates={'predicate_uuid1': PredicateGE('age', 18),
                                            'predicate_uuid2': PredicateGE('height', 180)})
    with pytest.raises(ValueError):
        await presentProofAndVerify(verifier, proofRequest, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testNonceShouldBeSame(prover1, verifier, claimsProver1Gvt, nonce,
                                genNonce):
    proofRequest = ProofRequest("proof1", "1.0", verifier.generateNonce(),
                                verifiableAttributes={'attr_uuid': AttributeInfo(name='name')})

    proof = await prover1.presentProof(proofRequest)

    proofRequest = ProofRequest("proof1", "1.0", genNonce,
                                verifiableAttributes=proofRequest.verifiableAttributes,
                                predicates=proofRequest.predicates)
    assert not await verifier.verify(proofRequest, proof)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testUParamShouldBeSame(prover1, verifier, issuerGvt, schemaGvtId,
                                 attrsProver1Gvt, keysGvt,
                                 issueAccumulatorGvt):
    claimsReq = await prover1.createClaimRequest(schemaGvtId)

    claimsReq = claimsReq._replace(U=claimsReq.U ** 2)
    claim_signature, claim_attributes = await issuerGvt.issueClaim(schemaGvtId, claimsReq)
    await prover1.processClaim(schemaGvtId, claim_attributes, claim_signature)

    proofRequest = ProofRequest("proof1", "1.0", verifier.generateNonce(),
                                verifiableAttributes={'attr_uuid': AttributeInfo(name='name')},
                                predicates={})
    assert not await presentProofAndVerify(verifier, proofRequest, prover1)


@pytest.mark.asyncio
async def testUrParamShouldBeSame(prover1, issuerGvt, schemaGvtId,
                                  attrsProver1Gvt, keysGvt,
                                  issueAccumulatorGvt):
    claimsReq = await prover1.createClaimRequest(schemaGvtId)

    claimsReq = claimsReq._replace(Ur=claimsReq.Ur ** 2)
    claim_signature, claim_attributes = await issuerGvt.issueClaim(schemaGvtId, claimsReq)

    with pytest.raises(ValueError):
        await prover1.processClaim(schemaGvtId, claim_attributes, claim_signature)
