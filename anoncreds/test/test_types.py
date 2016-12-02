from anoncreds.protocol.types import PublicKey, ClaimDefinition, Claims, ProofInput, PredicateGE, FullProof, \
    ClaimDefinitionKey, ClaimRequest
from anoncreds.test.conftest import presentProof
from config.config import cmod


def testClaimDefKeyFromToDict():
    claimDefKey = ClaimDefinitionKey(name='claimDefName', version='1.0', issuerId='issuer1')
    assert claimDefKey == ClaimDefinitionKey.fromStrDict(claimDefKey.toStrDict())


def testClaimDefFromToDict():
    claimDef = ClaimDefinition(name='claimDefName', version='1.0', type='CL',
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


def testRequestClaimsFromToDict(claimsRequestProver1Gvt):
    assert claimsRequestProver1Gvt == ClaimRequest.fromStrDict(claimsRequestProver1Gvt.toStrDict())


def testClaimsFromToDict(claimsProver1Gvt):
    assert claimsProver1Gvt == Claims.fromStrDict(claimsProver1Gvt.toStrDict())


def testClaimProofFromToDict(prover1, nonce, claimsProver1Gvt):
    proofInput = ProofInput(['name'], [PredicateGE('age', 18)])
    proof = presentProof(prover1, proofInput, nonce)
    assert proof == FullProof.fromStrDict(proof.toStrDict())


def testProofInputFromToDict():
    proofInput = ProofInput(['name', 'age'], [PredicateGE('age', 18), PredicateGE('age', 25)])
    assert proofInput == ProofInput.fromStrDict(proofInput.toStrDict())
