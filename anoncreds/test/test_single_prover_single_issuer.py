import pytest

from anoncreds.protocol.types import ProofInput, PredicateGE, Claims, \
    ProofClaims, AttributeInfo
from anoncreds.test.conftest import presentProofAndVerify


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testPrimaryClaimOnlyEmpty(prover1, verifier, claimsProver1Gvt, nonce):
    proofInput = ProofInput(nonce, {})
    claims, requestedProof = await prover1._findClaims(proofInput)
    claims = {schemaId: ProofClaims(
        Claims(primaryClaim=proofClaim.claims.primaryClaim))
              for schemaId, proofClaim in claims.items()}

    proof = await prover1._prepareProof(claims, proofInput.nonce, requestedProof)

    assert await verifier.verify(proofInput, proof)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testPrimaryClaimNoPredicates(prover1, verifier, claimsProver1Gvt,
                                       nonce, schemaGvtId):
    proofInput = ProofInput(nonce=nonce, revealedAttrs={'uuid1': AttributeInfo(name='name')}, predicates={})

    claims, requestedProof = await prover1._findClaims(proofInput)
    claims = {
        schemaId: ProofClaims(
            Claims(primaryClaim=proofClaim.claims.primaryClaim), [AttributeInfo(name='name')], [])
        for schemaId, proofClaim in claims.items()}
    proof = await prover1._prepareProof(claims, proofInput.nonce, requestedProof)

    assert await verifier.verify(proofInput, proof)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testPrimaryClaimPredicatesOnly(prover1, verifier, claimsProver1Gvt,
                                         nonce, schemaGvtId):
    predicate = PredicateGE('age', 18)
    proofInput = ProofInput(nonce=nonce, predicates={'uuid': predicate})
    claims, requestedProof = await prover1._findClaims(proofInput)
    claims = {
        schemaId: ProofClaims(
            Claims(primaryClaim=proofClaim.claims.primaryClaim), predicates=[predicate])
        for schemaId, proofClaim in claims.items()}

    proof = await prover1._prepareProof(claims, proofInput.nonce, requestedProof)

    assert await verifier.verify(proofInput, proof)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testEmpty(prover1, verifier, claimsProver1Gvt):
    assert await presentProofAndVerify(verifier, ProofInput(), prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testNoPredicates(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(revealedAttrs={'uuid': AttributeInfo(name='name')}, predicates={})
    assert await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipleRevealedAttrs(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(revealedAttrs={'uuid1': AttributeInfo(name='name'),
                                           'uuid2': AttributeInfo(name='sex')}, predicates={})
    assert await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testGePredicate(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(revealedAttrs={'attr_uuid': AttributeInfo(name='name')},
                            predicates={'predicate_uuid': PredicateGE('age', 18)})
    assert await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testGePredicateForEqual(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(revealedAttrs={'attr_uuid': AttributeInfo(name='name')},
                            predicates={'predicate_uuid': PredicateGE('age', 28)})
    assert await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testGePredicateNegative(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(revealedAttrs={'attr_uuid': AttributeInfo(name='name')},
                            predicates={'predicate_uuid': PredicateGE('age', 29)})
    with pytest.raises(ValueError):
        await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipleGePredicate(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(revealedAttrs={'attr_uuid': AttributeInfo(name='name')},
                            predicates={'predicate_uuid1': PredicateGE('age', 18),
                                        'predicate_uuid2': PredicateGE('height', 170)})
    assert await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipleGePredicateNegative(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(revealedAttrs={'attr_uuid': AttributeInfo(name='name')},
                            predicates={'predicate_uuid1': PredicateGE('age', 18),
                                        'predicate_uuid2': PredicateGE('height', 180)})
    with pytest.raises(ValueError):
        await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testNonceShouldBeSame(prover1, verifier, claimsProver1Gvt, nonce,
                                genNonce):
    nonce = verifier.generateNonce()
    proofInput = ProofInput(nonce, {'attr_uuid': AttributeInfo(name='name')})

    proof = await prover1.presentProof(proofInput)

    proofInput = ProofInput(genNonce, proofInput.revealedAttrs, proofInput.predicates)
    assert not await verifier.verify(proofInput, proof)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testUParamShouldBeSame(prover1, verifier, issuerGvt, schemaGvtId,
                                 attrsProver1Gvt, keysGvt,
                                 issueAccumulatorGvt):
    claimsReq = await prover1.createClaimRequest(schemaGvtId)

    claimsReq = claimsReq._replace(U=claimsReq.U ** 2)
    claim_signature, claim_attributes = await issuerGvt.issueClaim(schemaGvtId, claimsReq)
    await prover1.processClaim(schemaGvtId, claim_attributes, claim_signature)

    proofInput = ProofInput(revealedAttrs={'attr_uuid': AttributeInfo(name='name')},
                            predicates={})
    assert not await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.asyncio
async def testUrParamShouldBeSame(prover1, issuerGvt, schemaGvtId,
                                  attrsProver1Gvt, keysGvt,
                                  issueAccumulatorGvt):
    claimsReq = await prover1.createClaimRequest(schemaGvtId)

    claimsReq = claimsReq._replace(Ur=claimsReq.Ur ** 2)
    claim_signature, claim_attributes = await issuerGvt.issueClaim(schemaGvtId, claimsReq)

    with pytest.raises(ValueError):
        await prover1.processClaim(schemaGvtId, claim_attributes, claim_signature)
