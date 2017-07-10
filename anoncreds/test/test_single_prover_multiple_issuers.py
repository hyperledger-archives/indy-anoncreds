import pytest

from anoncreds.protocol.types import ProofInput, PredicateGE, AttributeInfo
from anoncreds.test.conftest import presentProofAndVerify


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testNoPredicates(prover1, verifier, claimsProver1):
    proofInput = ProofInput(revealedAttrs={'uuid1': AttributeInfo(name='name'),
                                           'uuid2': AttributeInfo(name='status')}, predicates={})
    assert await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testGePredicate(prover1, verifier, claimsProver1):
    proofInput = ProofInput(revealedAttrs={'attr_uuid': AttributeInfo(name='name')},
                            predicates={'predicate_uuid': PredicateGE('period', 5)})
    assert await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testGePredicateForEqual(prover1, verifier, claimsProver1):
    proofInput = ProofInput(revealedAttrs={'attr_uuid': AttributeInfo(name='name')},
                            predicates={'predicate_uuid': PredicateGE('period', 8)})
    assert await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testGePredicateNegative(prover1, verifier, claimsProver1):
    proofInput = ProofInput(revealedAttrs={'attr_uuid': AttributeInfo(name='name')},
                            predicates={'predicate_uuid': PredicateGE('period', 9)})
    with pytest.raises(ValueError):
        await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipleGePredicate(prover1, verifier, claimsProver1):
    proofInput = ProofInput(revealedAttrs={'attr_uuid': AttributeInfo(name='name')},
                            predicates={'predicate_uuid1': PredicateGE('age', 18),
                                        'predicate_uuid2': PredicateGE('period', 5)})
    await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipleGePredicateMultipleRevealed(prover1, verifier,
                                                  claimsProver1):
    proofInput = ProofInput(revealedAttrs={'attr_uuid1': AttributeInfo(name='name'),
                                           'attr_uuid2': AttributeInfo(name='status')},
                            predicates={'predicate_uuid1': PredicateGE('age', 18),
                                        'predicate_uuid2': PredicateGE('period', 5)})
    await presentProofAndVerify(verifier, proofInput, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultipleGePredicateNegative(prover1, verifier, claimsProver1):
    proofInput = ProofInput(revealedAttrs={'attr_uuid': AttributeInfo(name='name')},
                            predicates={'predicate_uuid1': PredicateGE('age', 18),
                                        'predicate_uuid2': PredicateGE('period', 9)})
    with pytest.raises(ValueError):
        await presentProofAndVerify(verifier, proofInput, prover1)
