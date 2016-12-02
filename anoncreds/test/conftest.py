import pytest

from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.prover import Prover
from anoncreds.protocol.repo.attributes_repo import AttributeRepoInMemory
from anoncreds.protocol.repo.public_repo import PublicRepoInMemory
from anoncreds.protocol.types import AttribDef, AttribType, ID, ProofInput
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
def claimDefGvt(issuerGvt):
    return issuerGvt.genClaimDef("GVT", "1.0", GVT.attribNames())


@pytest.fixture(scope="function")
def claimDefXyz(issuerXyz):
    return issuerXyz.genClaimDef("XYZCorp", "1.0", XYZCorp.attribNames())


@pytest.fixture(scope="function")
def claimDefGvtId(claimDefGvt):
    return ID(claimDefGvt.getKey())


@pytest.fixture(scope="function")
def claimDefXyzId(claimDefXyz):
    return ID(claimDefXyz.getKey())


@pytest.fixture(scope="function")
def keysGvt(primes1, issuerGvt, claimDefGvtId):
    issuerGvt.genKeys(claimDefGvtId, **primes1)


@pytest.fixture(scope="function")
def pkGvt(keysGvt, issuerWallet1, claimDefGvtId):
    return issuerWallet1.getPublicKey(claimDefGvtId)


@pytest.fixture(scope="function")
def keysXyz(primes2, issuerXyz, claimDefXyzId):
    issuerXyz.genKeys(claimDefXyzId, **primes2)


@pytest.fixture(scope="function")
def issueAccumulatorGvt(claimDefGvtId, issuerGvt, keysGvt):
    issuerGvt.issueAccumulator(id=claimDefGvtId, iA=iA1, L=L)


@pytest.fixture(scope="function")
def issueAccumulatorXyz(claimDefXyzId, issuerXyz, keysXyz):
    issuerXyz.issueAccumulator(id=claimDefXyzId, iA=iA2, L=L)


@pytest.fixture(scope="function")
def attrsProver1Gvt(attrRepo, claimDefGvt):
    attrs = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    attrRepo.addAttributes(claimDefGvt.getKey(), proverId1, attrs)
    return attrs


@pytest.fixture(scope="function")
def attrsProver2Gvt(attrRepo, claimDefGvt):
    attrs = GVT.attribs(name='Jason', age=42, height=180, sex='male')
    attrRepo.addAttributes(claimDefGvt.getKey(), proverId2, attrs)
    return attrs


@pytest.fixture(scope="function")
def attrsProver1Xyz(attrRepo, claimDefXyz):
    attrs = XYZCorp.attribs(status='partial', period=8)
    attrRepo.addAttributes(claimDefXyz.getKey(), proverId1, attrs)
    return attrs


@pytest.fixture(scope="function")
def attrsProver2Xyz(attrRepo, claimDefXyz):
    attrs = XYZCorp.attribs(status='full-time', period=22)
    attrRepo.addAttributes(claimDefXyz.getKey(), proverId2, attrs)
    return attrs


@pytest.fixture(scope="function")
def revealedGvtNameProver1(attrRepo, attrsProver1Gvt, claimDefGvt):
    return attrRepo.getRevealedAttributes(claimDefGvt.getKey(), proverId1, ['name']).encoded()


@pytest.fixture(scope="function")
def revealedGvtNameProver2(attrRepo, attrsProver2Gvt, claimDefGvt):
    return attrRepo.getRevealedAttributes(claimDefGvt.getKey(), proverId2, ['name']).encoded()

@pytest.fixture(scope="function")
def claimsRequestProver1Gvt(prover1, claimDefGvtId, keysGvt, issueAccumulatorGvt):
    return prover1.createClaimRequest(claimDefGvtId)

@pytest.fixture(scope="function")
def claimsProver1Gvt(prover1, issuerGvt, claimsRequestProver1Gvt, claimDefGvtId, attrsProver1Gvt):
    claims = issuerGvt.issueClaim(claimDefGvtId, claimsRequestProver1Gvt)
    prover1.processClaim(claimDefGvtId, claims)
    return prover1.wallet.getClaims(claimDefGvtId)


@pytest.fixture(scope="function")
def claimsProver2Gvt(prover2, issuerGvt, claimDefGvtId, attrsProver2Gvt, keysGvt, issueAccumulatorGvt):
    claimsReq = prover2.createClaimRequest(claimDefGvtId)
    claims = issuerGvt.issueClaim(claimDefGvtId, claimsReq)
    prover2.processClaim(claimDefGvtId, claims)
    return prover2.wallet.getClaims(claimDefGvtId)


@pytest.fixture(scope="function")
def claimsProver1Xyz(prover1, issuerXyz, claimDefXyzId, attrsProver1Xyz, keysXyz, issueAccumulatorXyz):
    claimsReq = prover1.createClaimRequest(claimDefXyzId)
    claims = issuerXyz.issueClaim(claimDefXyzId, claimsReq)
    prover1.processClaim(claimDefXyzId, claims)
    return prover1.wallet.getClaims(claimDefXyzId)


@pytest.fixture(scope="function")
def claimsProver2Xyz(prover2, issuerXyz, claimDefXyzId, attrsProver2Xyz, keysXyz, issueAccumulatorXyz):
    claimsReq = prover2.createClaimRequest(claimDefXyzId)
    claims = issuerXyz.issueClaim(claimDefXyzId, claimsReq)
    prover2.processClaim(claimDefXyzId, claims)
    return prover2.wallet.getClaims(claimDefXyzId)


@pytest.fixture(scope="function")
def claimsProver1(claimsProver1Gvt, claimsProver1Xyz):
    return (claimsProver1Gvt, claimsProver1Xyz)


@pytest.fixture(scope="function")
def claimsProver2(claimsProver2Gvt, claimsProver2Xyz):
    return (claimsProver2Gvt, claimsProver2Xyz)


@pytest.fixture(scope="function")
def allClaims(claimsProver1, claimsProver2):
    return (claimsProver1, claimsProver2)


@pytest.fixture(scope="function")
def nonce(verifier):
    return verifier.generateNonce()


@pytest.fixture(scope="function")
def genNonce(verifier):
    return verifier.generateNonce()


def verifyProof(verifier, proof, nonce, prover, attrRepo, proofInput):
    revealedAttrs = attrRepo.getRevealedAttributesForProver(prover, proofInput.revealedAttrs).encoded()
    return verifier.verify(proofInput, proof, revealedAttrs, nonce)


def presentProof(prover, proofInput: ProofInput, nonce):
    return prover.presentProof(proofInput, nonce)


def presentProofAndVerify(verifier, proofInput: ProofInput, prover, attrRepo):
    nonce = verifier.generateNonce()
    proof = presentProof(prover, proofInput, nonce)
    return verifyProof(verifier, proof, nonce, prover, attrRepo, proofInput)
