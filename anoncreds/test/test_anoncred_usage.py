from anoncreds.protocol.fetcher import SimpleFetcher
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


def testSingleIssuerSingleProver(primes1):
    # 1. Init entities
    publicRepo = PublicRepoInMemory()
    attrRepo = AttributeRepoInMemory()
    issuer = Issuer(IssuerWalletInMemory('issuer1', publicRepo), attrRepo)

    # 2. Create a Claim Def
    claimDef = issuer.genClaimDef('GVT', '1.0', GVT.attribNames())
    claimDefId = ID(claimDef.getKey())

    # 3. Create keys for the Claim Def
    issuer.genKeys(claimDefId, **primes1)

    # 4. Issue accumulator
    issuer.issueAccumulator(id=claimDefId, iA=110, L=5)

    # 4. set attributes for user1
    userId = 111
    attrs = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    attrRepo.addAttributes(claimDef.getKey(), userId, attrs)

    # 5. request Claims
    prover = Prover(ProverWalletInMemory(userId, publicRepo))
    prover.requestClaim(claimDefId, SimpleFetcher(issuer))

    # 6. proof Claims
    proofInput = ProofInput(
        ['name'],
        [PredicateGE('age', 18)])

    verifier = Verifier(WalletInMemory('verifier1', publicRepo))
    nonce = verifier.generateNonce()
    proof = prover.presentProof(proofInput, nonce)
    revealedAttrs = attrRepo.getRevealedAttributesForProver(prover, proofInput.revealedAttrs).encoded()
    assert verifier.verify(proofInput, proof, revealedAttrs, nonce)


def testMultiplIssuersSingleProver(primes1, primes2):
    # 1. Init entities
    publicRepo = PublicRepoInMemory()
    attrRepo = AttributeRepoInMemory()
    issuer1 = Issuer(IssuerWalletInMemory('issuer1', publicRepo), attrRepo)
    issuer2 = Issuer(IssuerWalletInMemory('issuer2', publicRepo), attrRepo)

    # 2. Create a Claim Def
    claimDef1 = issuer1.genClaimDef('GVT', '1.0', GVT.attribNames())
    claimDefId1 = ID(claimDef1.getKey())
    claimDef2 = issuer2.genClaimDef('XYZCorp', '1.0', XYZCorp.attribNames())
    claimDefId2 = ID(claimDef2.getKey())

    # 3. Create keys for the Claim Def
    issuer1.genKeys(claimDefId1, **primes1)
    issuer2.genKeys(claimDefId2, **primes2)

    # 4. Issue accumulator
    issuer1.issueAccumulator(id=claimDefId1, iA=110, L=5)
    issuer2.issueAccumulator(id=claimDefId2, iA=9999999, L=5)

    # 4. set attributes for user1
    userId = 111
    attrs1 = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    attrs2 = XYZCorp.attribs(status='FULL', period=8)
    attrRepo.addAttributes(claimDef1.getKey(), userId, attrs1)
    attrRepo.addAttributes(claimDef2.getKey(), userId, attrs2)

    # 5. request Claims
    prover = Prover(ProverWalletInMemory(userId, publicRepo))
    prover.requestClaim(claimDefId1, SimpleFetcher(issuer1))
    prover.requestClaim(claimDefId2, SimpleFetcher(issuer2))

    # 6. proof Claims
    proofInput = ProofInput(['name', 'status'],
                            [PredicateGE('age', 18), PredicateGE('period', 5)])

    verifier = Verifier(WalletInMemory('verifier1', publicRepo))
    nonce = verifier.generateNonce()
    proof = prover.presentProof(proofInput, nonce)

    revealedAttrs = attrRepo.getRevealedAttributesForProver(prover, proofInput.revealedAttrs).encoded()
    assert verifier.verify(proofInput, proof, revealedAttrs, nonce)


def testSingleIssuerMultipleCredDefsSingleProver(primes1, primes2):
    # 1. Init entities
    publicRepo = PublicRepoInMemory()
    attrRepo = AttributeRepoInMemory()
    issuer = Issuer(IssuerWalletInMemory('issuer1', publicRepo), attrRepo)

    # 2. Create a Claim Def
    claimDef1 = issuer.genClaimDef('GVT', '1.0', GVT.attribNames())
    claimDefId1 = ID(claimDef1.getKey())
    claimDef2 = issuer.genClaimDef('XYZCorp', '1.0', XYZCorp.attribNames())
    claimDefId2 = ID(claimDef2.getKey())

    # 3. Create keys for the Claim Def
    issuer.genKeys(claimDefId1, **primes1)
    issuer.genKeys(claimDefId2, **primes2)

    # 4. Issue accumulator
    issuer.issueAccumulator(id=claimDefId1, iA=110, L=5)
    issuer.issueAccumulator(id=claimDefId2, iA=9999999, L=5)

    # 4. set attributes for user1
    userId = 111
    attrs1 = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    attrs2 = XYZCorp.attribs(status='FULL', period=8)
    attrRepo.addAttributes(claimDef1.getKey(), userId, attrs1)
    attrRepo.addAttributes(claimDef2.getKey(), userId, attrs2)

    # 5. request Claims
    prover = Prover(ProverWalletInMemory(userId, publicRepo))
    prover.requestClaim(claimDefId1, SimpleFetcher(issuer))
    prover.requestClaim(claimDefId2, SimpleFetcher(issuer))

    # 6. proof Claims
    proofInput = ProofInput(
        ['name'],
        [PredicateGE('age', 18), PredicateGE('period', 5)])

    verifier = Verifier(WalletInMemory('verifier1', publicRepo))
    nonce = verifier.generateNonce()
    proof = prover.presentProof(proofInput, nonce)

    revealedAttrs = attrRepo.getRevealedAttributesForProver(prover, proofInput.revealedAttrs).encoded()
    assert verifier.verify(proofInput, proof, revealedAttrs, nonce)

def testSingleIssuerSingleProverPrimaryOnly(primes1):
    # 1. Init entities
    publicRepo = PublicRepoInMemory()
    attrRepo = AttributeRepoInMemory()
    issuer = Issuer(IssuerWalletInMemory('issuer1', publicRepo), attrRepo)

    # 2. Create a Claim Def
    claimDef = issuer.genClaimDef('GVT', '1.0', GVT.attribNames())
    claimDefId = ID(claimDef.getKey())

    # 3. Create keys for the Claim Def
    issuer.genKeys(claimDefId, **primes1)

    # 4. Issue accumulator
    issuer.issueAccumulator(id=claimDefId, iA=110, L=5)

    # 4. set attributes for user1
    userId = 111
    attrs = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    attrRepo.addAttributes(claimDef.getKey(), userId, attrs)

    # 5. request Claims
    prover = Prover(ProverWalletInMemory(userId, publicRepo))
    prover.requestClaim(claimDefId, SimpleFetcher(issuer), False)

    # 6. proof Claims
    proofInput = ProofInput(
        ['name'],
        [PredicateGE('age', 18)])

    verifier = Verifier(WalletInMemory('verifier1', publicRepo))
    nonce = verifier.generateNonce()
    proof = prover.presentProof(proofInput, nonce)
    revealedAttrs = attrRepo.getRevealedAttributesForProver(prover, proofInput.revealedAttrs).encoded()
    assert verifier.verify(proofInput, proof, revealedAttrs, nonce)