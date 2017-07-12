import pytest

from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.prover import Prover
from anoncreds.protocol.repo.attributes_repo import AttributeRepoInMemory
from anoncreds.protocol.repo.public_repo import PublicRepoInMemory
from anoncreds.protocol.types import AttribDef, AttribType, ID, ProofRequest
from anoncreds.protocol.verifier import Verifier
from anoncreds.protocol.wallet.issuer_wallet import IssuerWalletInMemory
from anoncreds.protocol.wallet.prover_wallet import ProverWalletInMemory
from anoncreds.protocol.wallet.wallet import WalletInMemory
from config.config import cmod

#
primes = {
    "prime1":
        (cmod.integer(
            157329491389375793912190594961134932804032426403110797476730107804356484516061051345332763141806005838436304922612495876180233509449197495032194146432047460167589034147716097417880503952139805241591622353828629383332869425029086898452227895418829799945650973848983901459733426212735979668835984691928193677469),
         cmod.integer(
             151323892648373196579515752826519683836764873607632072057591837216698622729557534035138587276594156320800768525825023728398410073692081011811496168877166664537052088207068061172594879398773872352920912390983199416927388688319207946493810449203702100559271439586753256728900713990097168484829574000438573295723))
    , "prime2":
        (cmod.integer(
            150619677884468353208058156632953891431975271416620955614548039937246769610622017033385394658879484186852231469238992217246264205570458379437126692055331206248530723117202131739966737760399755490935589223401123762051823602343810554978803032803606907761937587101969193241921351011430750970746500680609001799529),
         cmod.integer(
             171590857568436644992359347719703764048501078398666061921719064395827496970696879481740311141148273607392657321103691543916274965279072000206208571551864201305434022165176563363954921183576230072812635744629337290242954699427160362586102068962285076213200828451838142959637006048439307273563604553818326766703))
}

GVT = AttribDef('gvt',
                [AttribType('name', encode=True),
                 AttribType('age', encode=False),
                 AttribType('height', encode=False),
                 AttribType('sex', encode=True)])
XYZCorp = AttribDef('xyz',
                    [AttribType('status', encode=True),
                     AttribType('period', encode=False)])
# NASEMP = GVT + XYZCorp
#
iA1 = 100
iA2 = 101
#
proverId1 = 222
proverId2 = 333
#
# verifierId1 = 555
#
L = 5


#
#
# ############ module scope
#
#

@pytest.fixture(scope="module")
def primes1():
    P_PRIME1, Q_PRIME1 = primes.get("prime1")
    return dict(p_prime=P_PRIME1, q_prime=Q_PRIME1)


#
#
@pytest.fixture(scope="module")
def primes2():
    P_PRIME2, Q_PRIME2 = primes.get("prime2")
    return dict(p_prime=P_PRIME2, q_prime=Q_PRIME2)


@pytest.fixture(scope="function")
def attrRepo():
    return AttributeRepoInMemory()


@pytest.fixture(scope="function")
def publicRepo():
    return PublicRepoInMemory()


@pytest.fixture(scope="function")
def issuerWallet1(publicRepo):
    return IssuerWalletInMemory('issuer1', publicRepo)


@pytest.fixture(scope="function")
def issuerWallet2(publicRepo):
    return IssuerWalletInMemory('issuer2', publicRepo)


@pytest.fixture(scope="function")
def issuerGvt(issuerWallet1, attrRepo):
    return Issuer(issuerWallet1, attrRepo)


@pytest.fixture(scope="function")
def issuerXyz(issuerWallet2, attrRepo):
    return Issuer(issuerWallet2, attrRepo)


@pytest.fixture(scope="function")
def proverWallet1(publicRepo):
    return ProverWalletInMemory(proverId1, publicRepo)


@pytest.fixture(scope="function")
def proverWallet2(publicRepo):
    return ProverWalletInMemory(proverId2, publicRepo)


@pytest.fixture(scope="function")
def prover1(proverWallet1):
    return Prover(proverWallet1)


@pytest.fixture(scope="function")
def prover2(proverWallet2):
    return Prover(proverWallet2)


@pytest.fixture(scope="function")
def verifier(publicRepo):
    return Verifier(WalletInMemory('verifier1', publicRepo))


@pytest.fixture(scope="function")
def schemaGvt(issuerGvt, event_loop):
    return event_loop.run_until_complete(
        issuerGvt.genSchema("GVT", "1.0", GVT.attribNames()))


@pytest.fixture(scope="function")
def schemaXyz(issuerXyz, event_loop):
    return event_loop.run_until_complete(
        issuerXyz.genSchema("XYZCorp", "1.0", XYZCorp.attribNames()))


@pytest.fixture(scope="function")
def schemaGvtId(schemaGvt):
    return ID(schemaGvt.getKey())


@pytest.fixture(scope="function")
def schemaXyzId(schemaXyz):
    return ID(schemaXyz.getKey())


@pytest.fixture(scope="function")
def keysGvt(primes1, issuerGvt, schemaGvtId, event_loop):
    return event_loop.run_until_complete(issuerGvt.genKeys(schemaGvtId,
                                                           **primes1))


@pytest.fixture(scope="function")
def keysXyz(primes2, issuerXyz, schemaXyzId, event_loop):
    return event_loop.run_until_complete(issuerXyz.genKeys(schemaXyzId,
                                                           **primes2))


@pytest.fixture(scope="function")
def issueAccumulatorGvt(schemaGvtId, issuerGvt, keysGvt, event_loop):
    event_loop.run_until_complete(
        issuerGvt.issueAccumulator(schemaId=schemaGvtId, iA=iA1, L=L))


@pytest.fixture(scope="function")
def issueAccumulatorXyz(schemaXyzId, issuerXyz, keysXyz, event_loop):
    event_loop.run_until_complete(
        issuerXyz.issueAccumulator(schemaId=schemaXyzId, iA=iA2, L=L))


@pytest.fixture(scope="function")
def attrsProver1Gvt(attrRepo, schemaGvt):
    attrs = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    attrRepo.addAttributes(schemaGvt.getKey(), proverId1, attrs)
    return attrs


@pytest.fixture(scope="function")
def attrsProver2Gvt(attrRepo, schemaGvt):
    attrs = GVT.attribs(name='Jason', age=42, height=180, sex='male')
    attrRepo.addAttributes(schemaGvt.getKey(), proverId2, attrs)
    return attrs


@pytest.fixture(scope="function")
def attrsProver1Xyz(attrRepo, schemaXyz):
    attrs = XYZCorp.attribs(status='partial', period=8)
    attrRepo.addAttributes(schemaXyz.getKey(), proverId1, attrs)
    return attrs


@pytest.fixture(scope="function")
def attrsProver2Xyz(attrRepo, schemaXyz):
    attrs = XYZCorp.attribs(status='full-time', period=22)
    attrRepo.addAttributes(schemaXyz.getKey(), proverId2, attrs)
    return attrs


@pytest.fixture(scope="function")
def claimsRequestProver1Gvt(prover1, schemaGvtId, keysGvt,
                            issueAccumulatorGvt, event_loop):
    return event_loop.run_until_complete(
        prover1.createClaimRequest(schemaGvtId))


@pytest.fixture(scope="function")
def claimsProver1Gvt(prover1, issuerGvt, claimsRequestProver1Gvt, schemaGvtId,
                     attrsProver1Gvt, event_loop):
    signature, claim = event_loop.run_until_complete(
        issuerGvt.issueClaim(schemaGvtId, claimsRequestProver1Gvt))
    event_loop.run_until_complete(prover1.processClaim(schemaGvtId, claim, signature))
    return event_loop.run_until_complete(
        prover1.wallet.getClaimSignature(schemaGvtId))


@pytest.fixture(scope="function")
def claimsProver2Gvt(prover2, issuerGvt, schemaGvtId, attrsProver2Gvt,
                     keysGvt, issueAccumulatorGvt, event_loop):
    claimsReq = event_loop.run_until_complete(
        prover2.createClaimRequest(schemaGvtId))
    signature, claim = event_loop.run_until_complete(
        issuerGvt.issueClaim(schemaGvtId, claimsReq))
    event_loop.run_until_complete(prover2.processClaim(schemaGvtId, claim, signature))
    return event_loop.run_until_complete(
        prover2.wallet.getClaimSignature(schemaGvtId))


@pytest.fixture(scope="function")
def claimsProver1Xyz(prover1, issuerXyz, schemaXyzId, attrsProver1Xyz,
                     keysXyz, issueAccumulatorXyz, event_loop):
    claimsReq = event_loop.run_until_complete(
        prover1.createClaimRequest(schemaXyzId))
    signature, claim = event_loop.run_until_complete(
        issuerXyz.issueClaim(schemaXyzId, claimsReq))
    event_loop.run_until_complete(prover1.processClaim(schemaXyzId, claim, signature))
    return event_loop.run_until_complete(
        prover1.wallet.getClaimSignature(schemaXyzId))


@pytest.fixture(scope="function")
def claimsProver2Xyz(prover2, issuerXyz, schemaXyzId, attrsProver2Xyz,
                     keysXyz, issueAccumulatorXyz, event_loop):
    claimsReq = event_loop.run_until_complete(
        prover2.createClaimRequest(schemaXyzId))
    signature, claim = event_loop.run_until_complete(
        issuerXyz.issueClaim(schemaXyzId, claimsReq))
    event_loop.run_until_complete(prover2.processClaim(schemaXyzId, claim, signature))
    return event_loop.run_until_complete(
        prover2.wallet.getClaimSignature(schemaXyzId))


@pytest.fixture(scope="function")
def claimsProver1(claimsProver1Gvt, claimsProver1Xyz):
    return claimsProver1Gvt, claimsProver1Xyz


@pytest.fixture(scope="function")
def claimsProver2(claimsProver2Gvt, claimsProver2Xyz):
    return claimsProver2Gvt, claimsProver2Xyz


@pytest.fixture(scope="function")
def allClaims(claimsProver1, claimsProver2):
    return claimsProver1, claimsProver2


@pytest.fixture(scope="function")
def nonce(verifier):
    return verifier.generateNonce()


@pytest.fixture(scope="function")
def genNonce(verifier):
    return verifier.generateNonce()


async def presentProofAndVerify(verifier: Verifier, proofRequest: ProofRequest, prover):
    proof = await prover.presentProof(proofRequest)
    return await verifier.verify(proofRequest, proof)