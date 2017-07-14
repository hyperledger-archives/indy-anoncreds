import pytest

from anoncreds.protocol.types import ProofRequest, ID, AttributeInfo
from anoncreds.protocol.utils import groupIdentityG1
from anoncreds.test.conftest import presentProofAndVerify


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testIssueRevocationCredential(claimsProver1Gvt, issuerGvt,
                                        schemaGvtId):
    nonRevocClaimGvtProver1 = claimsProver1Gvt.nonRevocClaim
    acc = await issuerGvt.wallet.getAccumulator(schemaGvtId)
    tails = await issuerGvt.wallet.getTails(schemaGvtId)
    assert nonRevocClaimGvtProver1
    assert nonRevocClaimGvtProver1.witness
    assert nonRevocClaimGvtProver1.witness.V
    assert nonRevocClaimGvtProver1.i == 1
    assert nonRevocClaimGvtProver1.witness.gi == tails.g[1]

    assert acc.V
    assert acc.acc != 1

    assert nonRevocClaimGvtProver1.witness.V == acc.V


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testRevoce(claimsProver1Gvt, issuerGvt, schemaGvtId):
    await issuerGvt.revoke(schemaGvtId, 1)
    newAcc = await issuerGvt.wallet.getAccumulator(schemaGvtId)
    assert not newAcc.V
    assert newAcc.acc == groupIdentityG1()


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testUpdateWitnessNotChangedIfInSync(claimsProver1Gvt, schemaGvt,
                                              prover1):
    nonRevocClaimGvtProver1 = claimsProver1Gvt.nonRevocClaim
    acc = await prover1.wallet.getAccumulator(ID(schemaId=schemaGvt.seqId))

    # not changed as in sync
    oldOmega = nonRevocClaimGvtProver1.witness.omega

    c2 = await prover1._nonRevocProofBuilder.updateNonRevocationClaim(
        schemaGvt.seqId,
        nonRevocClaimGvtProver1)
    assert c2.witness.V == acc.V
    assert oldOmega == c2.witness.omega


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testUpdateWitnessChangedIfOutOfSync(claimsProver1Gvt, issuerGvt,
                                              schemaGvt, prover1):
    nonRevocClaimGvtProver1 = claimsProver1Gvt.nonRevocClaim
    acc = await issuerGvt.wallet.getAccumulator(ID(schemaId=schemaGvt.seqId))

    # not in sync
    acc.V.add(3)
    assert nonRevocClaimGvtProver1.witness.V != acc.V

    # witness is updated
    oldOmega = nonRevocClaimGvtProver1.witness.omega
    c2 = await prover1._nonRevocProofBuilder.updateNonRevocationClaim(
        schemaGvt.seqId,
        nonRevocClaimGvtProver1)
    assert c2.witness.V == acc.V
    assert oldOmega != c2.witness.omega


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testUpdateRevocedWitness(claimsProver1Gvt, issuerGvt, schemaGvt,
                                   prover1):
    nonRevocClaimGvtProver1 = claimsProver1Gvt.nonRevocClaim
    await issuerGvt.revoke(ID(schemaId=schemaGvt.seqId), 1)
    with pytest.raises(ValueError):
        await prover1._nonRevocProofBuilder.updateNonRevocationClaim(
            schemaGvt.seqId, nonRevocClaimGvtProver1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testInitNonRevocClaim(schemaGvtId, prover1, issuerGvt,
                                attrsProver1Gvt, keysGvt, issueAccumulatorGvt):
    claimsReq = await prover1.createClaimRequest(schemaGvtId)
    claim_signature, claim_attributes = await issuerGvt.issueClaim(schemaGvtId, claimsReq)

    oldV = claim_signature.nonRevocClaim.v
    await prover1.processClaim(schemaGvtId, claim_attributes, claim_signature)
    newC2 = (await prover1.wallet.getClaimSignature(schemaGvtId)).nonRevocClaim
    vrPrime = (
        await prover1.wallet.getNonRevocClaimInitData(schemaGvtId)).vPrime

    assert oldV + vrPrime == newC2.v


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testCAndTauList(claimsProver1Gvt, schemaGvt, prover1):
    nonRevocClaimGvtProver1 = claimsProver1Gvt.nonRevocClaim
    proofRevBuilder = prover1._nonRevocProofBuilder
    assert await proofRevBuilder.testProof(schemaGvt.seqId,
                                           nonRevocClaimGvtProver1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testRevocedWithUpdateWitness(schemaGvtId, issuerGvt, prover1,
                                       verifier, claimsProver1Gvt):
    await issuerGvt.revoke(schemaGvtId, 1)

    proofRequest = ProofRequest("proof1", "1.0", verifier.generateNonce(),
                                verifiableAttributes={'attr_uuid': AttributeInfo(name='name')})
    with pytest.raises(ValueError):
        await presentProofAndVerify(verifier, proofRequest, prover1)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testRevocedWithoutUpdateWitness(schemaGvtId, issuerGvt, prover1,
                                          verifier, claimsProver1Gvt):
    proofRequest = ProofRequest("proof1", "1.0", verifier.generateNonce(),
                                verifiableAttributes={'attr_uuid': AttributeInfo(name='name')})

    proof = await prover1.presentProof(proofRequest)

    await issuerGvt.revoke(schemaGvtId, 1)

    return await verifier.verify(proofRequest, proof)
