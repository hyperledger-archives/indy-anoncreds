import pytest

from anoncreds.protocol.types import PublicKey, ClaimDefinition, Claims, \
    ProofInput, PredicateGE, FullProof, \
    ClaimDefinitionKey, ClaimRequest, Proof
from anoncreds.protocol.utils import toDictWithStrValues, fromDictWithStrValues
from config.config import cmod


def testClaimDefKeyFromToDict():
    claimDefKey = ClaimDefinitionKey(name='claimDefName', version='1.0',
                                     issuerId='issuer1')
    assert claimDefKey == ClaimDefinitionKey.fromStrDict(
        claimDefKey.toStrDict())


def testClaimDefFromToDict():
    claimDef = ClaimDefinition(name='claimDefName', version='1.0',
                               claimDefType='CL',
                               attrNames=['attr1', 'attr2', 'attr3'],
                               issuerId='issuer1')
    assert claimDef == ClaimDefinition.fromStrDict(claimDef.toStrDict())


def testPKFromToDict():
    pk = PublicKey(N=cmod.integer(11),
                   Rms=cmod.integer(12),
                   Rctxt=cmod.integer(13),
                   R={'a': cmod.integer(1), 'b': cmod.integer(2)},
                   S=cmod.integer(14),
                   Z=cmod.integer(15))
    assert pk == PublicKey.fromStrDict(pk.toStrDict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
def testRequestClaimsFromToDict(claimsRequestProver1Gvt):
    assert claimsRequestProver1Gvt == ClaimRequest.fromStrDict(
        claimsRequestProver1Gvt.toStrDict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
def testClaimsFromToDict(claimsProver1Gvt):
    assert claimsProver1Gvt == Claims.fromStrDict(claimsProver1Gvt.toStrDict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
def testClaimsFromToDictPrimaryOnly(claimsProver1Gvt):
    claims = Claims(primaryClaim=claimsProver1Gvt.primaryClaim)
    assert claims == Claims.fromStrDict(claims.toStrDict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testClaimProofFromToDict(prover1, nonce, claimsProver1Gvt):
    proofInput = ProofInput(['name'], [PredicateGE('age', 18)])
    proof, _ = await prover1.presentProof(proofInput, nonce)
    assert proof == FullProof.fromStrDict(proof.toStrDict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testClaimProofFromToDictPrimaryOnly(prover1, nonce, claimsProver1Gvt):
    proofInput = ProofInput(['name'], [PredicateGE('age', 18)])
    proof, _ = await prover1.presentProof(proofInput, nonce)

    proofs = [Proof(primaryProof=proof.proofs[0].primaryProof)]
    proof = proof._replace(proofs=proofs)
    assert proof == FullProof.fromStrDict(proof.toStrDict())


def testProofInputFromToDict():
    proofInput = ProofInput(['name', 'age'],
                            [PredicateGE('age', 18), PredicateGE('age', 25)])
    assert proofInput == ProofInput.fromStrDict(proofInput.toStrDict())


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testRevealedAttrsFromToDict(prover1, nonce, claimsProver1Gvt):
    proofInput = ProofInput(['name'], [PredicateGE('age', 18)])
    _, revealedAttrs = await prover1.presentProof(proofInput, nonce)
    assert revealedAttrs == fromDictWithStrValues(
        toDictWithStrValues(revealedAttrs))
