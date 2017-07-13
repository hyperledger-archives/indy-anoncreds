import pytest

from anoncreds.protocol.types import ProofRequest, PredicateGE, AttributeInfo
from anoncreds.test.conftest import presentProofAndVerify


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testNoPredicates(prover1, prover2, verifier, allClaims):
    proofRequest = ProofRequest("proof1", "1.0", verifier.generateNonce(),
                                verifiableAttributes={'attr_uuid1': AttributeInfo(name='name'),
                                                      'attr_uuid2': AttributeInfo(name='name')})

    assert await presentProofAndVerify(verifier, proofRequest, prover1)
    assert await presentProofAndVerify(verifier, proofRequest, prover2)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testGePredicate(prover1, prover2, verifier, allClaims):
    proofRequest = ProofRequest("proof1", "1.0", verifier.generateNonce(),
                                verifiableAttributes={'attr_uuid1': AttributeInfo(name='name')},
                                predicates={'predicate_uuid1': PredicateGE('age', 18),
                                            'predicate_uuid2': PredicateGE('period', 3)})
    assert await presentProofAndVerify(verifier, proofRequest, prover1)
    assert await presentProofAndVerify(verifier, proofRequest, prover2)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testGePredicateNegativeForOne(prover1, prover2, verifier, allClaims):
    proofRequest = ProofRequest("proof1", "1.0", verifier.generateNonce(),
                                verifiableAttributes={'attr_uuid1': AttributeInfo(name='name')},
                                predicates={'predicate_uuid1': PredicateGE('age', 18),
                                            'predicate_uuid2': PredicateGE('period', 9)})
    assert await presentProofAndVerify(verifier, proofRequest, prover2)
    with pytest.raises(ValueError):
        await presentProofAndVerify(verifier, proofRequest, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testGePredicateNegativeForBoth(prover1, prover2, verifier, allClaims):
    proofRequest = ProofRequest("proof1", "1.0", verifier.generateNonce(),
                                verifiableAttributes={'attr_uuid1': AttributeInfo(name='name')},
                                predicates={'predicate_uuid1': PredicateGE('age', 38),
                                            'predicate_uuid2': PredicateGE('period', 30)})
    with pytest.raises(ValueError):
        await presentProofAndVerify(verifier, proofRequest, prover1)
    with pytest.raises(ValueError):
        await presentProofAndVerify(verifier, proofRequest, prover2)
