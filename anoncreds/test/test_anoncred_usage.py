import pytest

from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.prover import Prover
from anoncreds.protocol.repo.attributes_repo import AttributeRepoInMemory
from anoncreds.protocol.repo.public_repo import PublicRepoInMemory
from anoncreds.protocol.types import ProofInput, PredicateGE, \
    ID
from anoncreds.protocol.verifier import Verifier
from anoncreds.protocol.wallet.issuer_wallet import IssuerWalletInMemory
from anoncreds.protocol.wallet.prover_wallet import ProverWalletInMemory
from anoncreds.protocol.wallet.wallet import WalletInMemory
from anoncreds.test.conftest import GVT, XYZCorp


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testSingleIssuerSingleProver(primes1):
    # 1. Init entities
    publicRepo = PublicRepoInMemory()
    attrRepo = AttributeRepoInMemory()
    issuer = Issuer(IssuerWalletInMemory('issuer1', publicRepo), attrRepo)

    # 2. Create a Claim Def
    claimDef = await issuer.genClaimDef('GVT', '1.0', GVT.attribNames())
    claimDefId = ID(claimDef.getKey())

    # 3. Create keys for the Claim Def
    await issuer.genKeys(claimDefId, **primes1)

    # 4. Issue accumulator
    await issuer.issueAccumulator(claimDefId=claimDefId, iA='110', L=5)

    # 4. set attributes for user1
    userId = '111'
    attrs = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    attrRepo.addAttributes(claimDef.getKey(), userId, attrs)

    # 5. request Claims
    prover = Prover(ProverWalletInMemory(userId, publicRepo))
    claimsReq = await prover.createClaimRequest(claimDefId)
    claims = await issuer.issueClaim(claimDefId, claimsReq)
    await prover.processClaim(claimDefId, claims)

    # 6. proof Claims
    proofInput = ProofInput(
        ['name'],
        [PredicateGE('age', 18)])

    verifier = Verifier(WalletInMemory('verifier1', publicRepo))
    nonce = verifier.generateNonce()
    proof, revealedAttrs = await prover.presentProof(proofInput, nonce)
    assert await verifier.verify(proofInput, proof, revealedAttrs, nonce)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testMultiplIssuersSingleProver(primes1, primes2):
    # 1. Init entities
    publicRepo = PublicRepoInMemory()
    attrRepo = AttributeRepoInMemory()
    issuer1 = Issuer(IssuerWalletInMemory('issuer1', publicRepo), attrRepo)
    issuer2 = Issuer(IssuerWalletInMemory('issuer2', publicRepo), attrRepo)

    # 2. Create a Claim Def
    claimDef1 = await issuer1.genClaimDef('GVT', '1.0', GVT.attribNames())
    claimDefId1 = ID(claimDef1.getKey())
    claimDef2 = await issuer2.genClaimDef('XYZCorp', '1.0',
                                          XYZCorp.attribNames())
    claimDefId2 = ID(claimDef2.getKey())

    # 3. Create keys for the Claim Def
    await issuer1.genKeys(claimDefId1, **primes1)
    await issuer2.genKeys(claimDefId2, **primes2)

    # 4. Issue accumulator
    await issuer1.issueAccumulator(claimDefId=claimDefId1, iA='110', L=5)
    await issuer2.issueAccumulator(claimDefId=claimDefId2, iA=9999999, L=5)

    # 4. set attributes for user1
    userId = '111'
    attrs1 = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    attrs2 = XYZCorp.attribs(status='FULL', period=8)
    attrRepo.addAttributes(claimDef1.getKey(), userId, attrs1)
    attrRepo.addAttributes(claimDef2.getKey(), userId, attrs2)

    # 5. request Claims
    prover = Prover(ProverWalletInMemory(userId, publicRepo))
    claimsReq1 = await prover.createClaimRequest(claimDefId1)
    claimsReq2 = await prover.createClaimRequest(claimDefId2)
    claims1 = await issuer1.issueClaim(claimDefId1, claimsReq1)
    claims2 = await issuer2.issueClaim(claimDefId2, claimsReq2)
    await prover.processClaim(claimDefId1, claims1)
    await prover.processClaim(claimDefId2, claims2)

    # 6. proof Claims
    proofInput = ProofInput(['name', 'status'],
                            [PredicateGE('age', 18), PredicateGE('period', 5)])

    verifier = Verifier(WalletInMemory('verifier1', publicRepo))
    nonce = verifier.generateNonce()
    proof, revealedAttrs = await prover.presentProof(proofInput, nonce)
    assert await verifier.verify(proofInput, proof, revealedAttrs, nonce)


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
@pytest.mark.asyncio
async def testSingleIssuerMultipleCredDefsSingleProver(primes1, primes2):
    # 1. Init entities
    publicRepo = PublicRepoInMemory()
    attrRepo = AttributeRepoInMemory()
    issuer = Issuer(IssuerWalletInMemory('issuer1', publicRepo), attrRepo)

    # 2. Create a Claim Def
    claimDef1 = await issuer.genClaimDef('GVT', '1.0', GVT.attribNames())
    claimDefId1 = ID(claimDef1.getKey())
    claimDef2 = await issuer.genClaimDef('XYZCorp', '1.0',
                                         XYZCorp.attribNames())
    claimDefId2 = ID(claimDef2.getKey())

    # 3. Create keys for the Claim Def
    await issuer.genKeys(claimDefId1, **primes1)
    await issuer.genKeys(claimDefId2, **primes2)

    # 4. Issue accumulator
    await issuer.issueAccumulator(claimDefId=claimDefId1, iA='110', L=5)
    await issuer.issueAccumulator(claimDefId=claimDefId2, iA=9999999, L=5)

    # 4. set attributes for user1
    userId = '111'
    attrs1 = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    attrs2 = XYZCorp.attribs(status='FULL', period=8)
    attrRepo.addAttributes(claimDef1.getKey(), userId, attrs1)
    attrRepo.addAttributes(claimDef2.getKey(), userId, attrs2)

    # 5. request Claims
    prover = Prover(ProverWalletInMemory(userId, publicRepo))
    claimsReqs = await prover.createClaimRequests([claimDefId1, claimDefId2])
    claims = await issuer.issueClaims(claimsReqs)
    await prover.processClaims(claims)

    # 6. proof Claims
    proofInput = ProofInput(
        ['name'],
        [PredicateGE('age', 18), PredicateGE('period', 5)])

    verifier = Verifier(WalletInMemory('verifier1', publicRepo))
    nonce = verifier.generateNonce()
    proof, revealedAttrs = await prover.presentProof(proofInput, nonce)
    assert await verifier.verify(proofInput, proof, revealedAttrs, nonce)


@pytest.mark.asyncio
async def testSingleIssuerSingleProverPrimaryOnly(primes1):
    # 1. Init entities
    publicRepo = PublicRepoInMemory()
    attrRepo = AttributeRepoInMemory()
    issuer = Issuer(IssuerWalletInMemory('issuer1', publicRepo), attrRepo)

    # 2. Create a Claim Def
    claimDef = await issuer.genClaimDef('GVT', '1.0', GVT.attribNames())
    claimDefId = ID(claimDef.getKey())

    # 3. Create keys for the Claim Def
    await issuer.genKeys(claimDefId, **primes1)

    # 4. Issue accumulator
    await issuer.issueAccumulator(claimDefId=claimDefId, iA='110', L=5)

    # 4. set attributes for user1
    userId = '111'
    attrs = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    attrRepo.addAttributes(claimDef.getKey(), userId, attrs)

    # 5. request Claims
    prover = Prover(ProverWalletInMemory(userId, publicRepo))
    claimsReq = await prover.createClaimRequest(claimDefId, None, False)
    claims = await issuer.issueClaim(claimDefId, claimsReq)
    await prover.processClaim(claimDefId, claims)

    # 6. proof Claims
    proofInput = ProofInput(
        ['name'],
        [PredicateGE('age', 18)])

    verifier = Verifier(WalletInMemory('verifier1', publicRepo))
    nonce = verifier.generateNonce()
    proof, revealedAttrs = await prover.presentProof(proofInput, nonce)
    assert await verifier.verify(proofInput, proof, revealedAttrs, nonce)
