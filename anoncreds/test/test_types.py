import pytest

from anoncreds.protocol.types import PublicKey, Schema, Claims, \
    ProofInput, PredicateGE, FullProof, \
    SchemaKey, ClaimRequest, Proof
from anoncreds.protocol.utils import toDictWithStrValues, fromDictWithStrValues
from config.config import cmod


def testSchemaKeyFromToDict():
    schemaKey = SchemaKey(name='schemaName', version='1.0',
                            issuerId='issuer1')
    assert schemaKey == SchemaKey.fromStrDict(
        schemaKey.toStrDict())


def testSchemaFromToDict():
    schema = Schema(name='schemaName',
                    version='1.0',
                    attrNames=['attr1', 'attr2', 'attr3'],
                    issuerId='issuer1')
    assert schema == Schema.fromStrDict(schema.toStrDict())


def testPKFromToDict():
    pk = PublicKey(N=cmod.integer(11),
                   Rms=cmod.integer(12),
                   Rctxt=cmod.integer(13),
                   R={'a': cmod.integer(1), 'b': cmod.integer(2)},
                   S=cmod.integer(14),
                   Z=cmod.integer(15))

    assert pk == PublicKey.fromStrDict(pk.toStrDict())


def test_pk_from_to_dict():
    pk = PublicKey(N=cmod.integer(12345),
                   Rms=cmod.integer(12) % cmod.integer(12345),
                   Rctxt=cmod.integer(13) % cmod.integer(12345),
                   R={'name': cmod.integer(1) % cmod.integer(12345), 'age': cmod.integer(2) % cmod.integer(12345)},
                   S=cmod.integer(14) % cmod.integer(12345),
                   Z=cmod.integer(15) % cmod.integer(12345))

    pk_serialized = {
        'n': '12345',
        'rms': '12',
        'rctxt': '13',
        'r': {
            'name': '1',
            'age': '2'
        },
        's': '14',
        'z': '15',
    }

    assert pk.to_str_dict() == pk_serialized
    assert pk == PublicKey.from_str_dict(pk_serialized)


def test_claim_request_from_to_dict():
    n = cmod.integer(12345)
    u = cmod.integer(12) % n
    prover_did = '123456789'
    claim_request = ClaimRequest(userId=prover_did, U=u, Ur=None)

    claim_request_serialized = {
        'prover_did': '123456789',
        'u': '12',
        'ur': None
    }

    assert claim_request.to_str_dict() == claim_request_serialized
    assert claim_request == ClaimRequest.from_str_dict(claim_request_serialized, n)


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
