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

    # 2. Create a Schema
    schema = await issuer.genSchema('GVT', '1.0', GVT.attribNames())
    schemaId = ID(schema.getKey())

    # 3. Create keys for the Schema
    await issuer.genKeys(schemaId, **primes1)

    # 4. Issue accumulator
    await issuer.issueAccumulator(schemaId=schemaId, iA='110', L=5)

    # 4. set attributes for user1
    userId = '111'
    attrs = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    attrRepo.addAttributes(schema.getKey(), userId, attrs)

    # 5. request Claims
    prover = Prover(ProverWalletInMemory(userId, publicRepo))
    claimsReq = await prover.createClaimRequest(schemaId)
    claims = await issuer.issueClaim(schemaId, claimsReq)
    await prover.processClaim(schemaId, claims)

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

    # 2. Create a Schema
    schema1 = await issuer1.genSchema('GVT', '1.0', GVT.attribNames())
    schemaId1 = ID(schema1.getKey())
    schema2 = await issuer2.genSchema('XYZCorp', '1.0',
                                        XYZCorp.attribNames())
    schemaId2 = ID(schema2.getKey())

    # 3. Create keys for the Schema
    await issuer1.genKeys(schemaId1, **primes1)
    await issuer2.genKeys(schemaId2, **primes2)

    # 4. Issue accumulator
    await issuer1.issueAccumulator(schemaId=schemaId1, iA='110', L=5)
    await issuer2.issueAccumulator(schemaId=schemaId2, iA=9999999, L=5)

    # 4. set attributes for user1
    userId = '111'
    attrs1 = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    attrs2 = XYZCorp.attribs(status='FULL', period=8)
    attrRepo.addAttributes(schema1.getKey(), userId, attrs1)
    attrRepo.addAttributes(schema2.getKey(), userId, attrs2)

    # 5. request Claims
    prover = Prover(ProverWalletInMemory(userId, publicRepo))
    claimsReq1 = await prover.createClaimRequest(schemaId1)
    claimsReq2 = await prover.createClaimRequest(schemaId2)
    claims1 = await issuer1.issueClaim(schemaId1, claimsReq1)
    claims2 = await issuer2.issueClaim(schemaId2, claimsReq2)
    await prover.processClaim(schemaId1, claims1)
    await prover.processClaim(schemaId2, claims2)

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

    # 2. Create a Schema
    schema1 = await issuer.genSchema('GVT', '1.0', GVT.attribNames())
    schemaId1 = ID(schema1.getKey())
    schema2 = await issuer.genSchema('XYZCorp', '1.0',
                                       XYZCorp.attribNames())
    schemaId2 = ID(schema2.getKey())

    # 3. Create keys for the Schema
    await issuer.genKeys(schemaId1, **primes1)
    await issuer.genKeys(schemaId2, **primes2)

    # 4. Issue accumulator
    await issuer.issueAccumulator(schemaId=schemaId1, iA='110', L=5)
    await issuer.issueAccumulator(schemaId=schemaId2, iA=9999999, L=5)

    # 4. set attributes for user1
    userId = '111'
    attrs1 = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    attrs2 = XYZCorp.attribs(status='FULL', period=8)
    attrRepo.addAttributes(schema1.getKey(), userId, attrs1)
    attrRepo.addAttributes(schema2.getKey(), userId, attrs2)

    # 5. request Claims
    prover = Prover(ProverWalletInMemory(userId, publicRepo))
    claimsReqs = await prover.createClaimRequests([schemaId1, schemaId2])
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

    # 2. Create a Schema
    schema = await issuer.genSchema('GVT', '1.0', GVT.attribNames())
    schemaId = ID(schema.getKey())

    # 3. Create keys for the Schema
    await issuer.genKeys(schemaId, **primes1)

    # 4. Issue accumulator
    await issuer.issueAccumulator(schemaId=schemaId, iA='110', L=5)

    # 4. set attributes for user1
    userId = '111'
    attrs = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    attrRepo.addAttributes(schema.getKey(), userId, attrs)

    # 5. request Claims
    prover = Prover(ProverWalletInMemory(userId, publicRepo))
    claimsReq = await prover.createClaimRequest(schemaId, None, False)
    claims = await issuer.issueClaim(schemaId, claimsReq)
    await prover.processClaim(schemaId, claims)

    # 6. proof Claims
    proofInput = ProofInput(
        ['name'],
        [PredicateGE('age', 18)])

    verifier = Verifier(WalletInMemory('verifier1', publicRepo))
    nonce = verifier.generateNonce()
    proof, revealedAttrs = await prover.presentProof(proofInput, nonce)
    assert await verifier.verify(proofInput, proof, revealedAttrs, nonce)
