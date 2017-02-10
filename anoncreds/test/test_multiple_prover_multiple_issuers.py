import pytest

from anoncreds.protocol.types import ProofInput, PredicateGE
from anoncreds.test.conftest import presentProofAndVerify


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testNoPredicates(prover1, prover2, verifier, allClaims):
    proofInput = ProofInput(['name', 'status'], [])
    assert await presentProofAndVerify(verifier, proofInput, prover1)
    assert await presentProofAndVerify(verifier, proofInput, prover2)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testGePredicate(prover1, prover2, verifier, allClaims):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('period', 3)])
    assert await presentProofAndVerify(verifier, proofInput, prover1)
    assert await presentProofAndVerify(verifier, proofInput, prover2)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testGePredicateNegativeForOne(prover1, prover2, verifier, allClaims):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('period', 9)])
    assert await presentProofAndVerify(verifier, proofInput, prover2)
    with pytest.raises(ValueError):
        await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testGePredicateNegativeForBoth(prover1, prover2, verifier, allClaims):
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18),
                             PredicateGE('period', 30)])
    with pytest.raises(ValueError):
        await presentProofAndVerify(verifier, proofInput, prover1)
    with pytest.raises(ValueError):
        await presentProofAndVerify(verifier, proofInput, prover2)
