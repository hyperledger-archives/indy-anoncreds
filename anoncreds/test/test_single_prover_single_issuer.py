import pytest

from anoncreds.protocol.types import ProofInput, PredicateGE, Claims, \
    ProofClaims
from anoncreds.test.conftest import presentProofAndVerify


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testPrimaryClaimOnlyEmpty(prover1, verifier, claimsProver1Gvt, nonce):
    proofInput = ProofInput([])
    claims, revealedAttrs = await prover1._findClaims(proofInput)
    claims = {schemaKey: ProofClaims(
        Claims(primaryClaim=proofClaim.claims.primaryClaim))
              for schemaKey, proofClaim in claims.items()}
    proof = await prover1._prepareProof(claims, nonce)
    assert await verifier.verify(proofInput, proof, revealedAttrs, nonce)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testPrimaryClaimNoPredicates(prover1, verifier, claimsProver1Gvt,
                                       nonce, schemaGvtId,
                                       attrRepo):
    revealledAttrs = ['name']
    proofInput = ProofInput(revealledAttrs)
    claims, revealedAttrs = await prover1._findClaims(proofInput)
    claims = {
        schemaKey: ProofClaims(
            Claims(primaryClaim=proofClaim.claims.primaryClaim),
            revealedAttrs=revealledAttrs)
        for schemaKey, proofClaim in claims.items()}
    proof = await prover1._prepareProof(claims, nonce)
    assert await verifier.verify(proofInput, proof, revealedAttrs, nonce)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testPrimaryClaimPredicatesOnly(prover1, verifier, claimsProver1Gvt,
                                         nonce, schemaGvtId,
                                         attrRepo):
    predicates = [PredicateGE('age', 18)]
    proofInput = ProofInput(predicates=predicates)
    claims, revealedAttrs = await prover1._findClaims(proofInput)
    claims = {schemaKey: ProofClaims(
        Claims(primaryClaim=proofClaim.claims.primaryClaim),
        predicates=predicates)
              for schemaKey, proofClaim in claims.items()}
    proof = await prover1._prepareProof(claims, nonce)
    assert await verifier.verify(proofInput, proof, revealedAttrs, nonce)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testEmpty(prover1, verifier, claimsProver1Gvt):
    assert await presentProofAndVerify(verifier, ProofInput(), prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testNoPredicates(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(['name'], [])
    assert await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipleRevealedAttrs(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(['name', 'sex'], [])
    assert await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testGePredicate(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(['name'], [PredicateGE('age', 18)])
    assert await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testGePredicateForEqual(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(['name'], [PredicateGE('age', 28)])
    assert await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testGePredicateNegative(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(['name'], [PredicateGE('age', 29)])
    with pytest.raises(ValueError):
        await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipleGePredicate(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('height', 170)])
    assert await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipleGePredicateNegative(prover1, verifier, claimsProver1Gvt):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('height', 180)])
    with pytest.raises(ValueError):
        await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testNonceShouldBeSame(prover1, verifier, claimsProver1Gvt, nonce,
                                genNonce):
    revealedAttrs = ['name']
    proofInput = ProofInput(revealedAttrs, [])
    proof, revealedAttrs = await prover1.presentProof(proofInput, nonce)
    assert not await verifier.verify(proofInput, proof, revealedAttrs, genNonce)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
def testAttrsInClaims(claimsProver1Gvt, attrsProver1Gvt):
    attrs = claimsProver1Gvt.primaryClaim.attrs
    encodedAttrs = claimsProver1Gvt.primaryClaim.encodedAttrs

    assert attrs
    assert encodedAttrs
    assert attrs == attrsProver1Gvt._vals
    assert encodedAttrs.keys() == attrsProver1Gvt.keys()


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testUParamShouldBeSame(prover1, verifier, issuerGvt, schemaGvtId,
                                 attrsProver1Gvt, keysGvt,
                                 issueAccumulatorGvt):
    claimsReq = await prover1.createClaimRequest(schemaGvtId)

    claimsReq = claimsReq._replace(U=claimsReq.U ** 2)
    claims = await issuerGvt.issueClaim(schemaGvtId, claimsReq)
    await prover1.processClaim(schemaGvtId, claims)

    proofInput = ProofInput(['name'], [])
    assert not await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.asyncio
async def testUrParamShouldBeSame(prover1, issuerGvt, schemaGvtId,
                                  attrsProver1Gvt, keysGvt,
                                  issueAccumulatorGvt):
    claimsReq = await prover1.createClaimRequest(schemaGvtId)

    claimsReq = claimsReq._replace(Ur=claimsReq.Ur ** 2)
    claims = await issuerGvt.issueClaim(schemaGvtId, claimsReq)

    with pytest.raises(ValueError):
        await prover1.processClaim(schemaGvtId, claims)
