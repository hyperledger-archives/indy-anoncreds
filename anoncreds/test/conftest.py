import pytest
from charm.core.math.integer import integer

from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.prover import Prover, ProverInitializer
from anoncreds.protocol.types import AttribDef, AttribType, SecretData, PublicData, Claims
from anoncreds.protocol.verifier import Verifier

primes = {
    "prime1":
        (integer(
            157329491389375793912190594961134932804032426403110797476730107804356484516061051345332763141806005838436304922612495876180233509449197495032194146432047460167589034147716097417880503952139805241591622353828629383332869425029086898452227895418829799945650973848983901459733426212735979668835984691928193677469),
         integer(
             151323892648373196579515752826519683836764873607632072057591837216698622729557534035138587276594156320800768525825023728398410073692081011811496168877166664537052088207068061172594879398773872352920912390983199416927388688319207946493810449203702100559271439586753256728900713990097168484829574000438573295723))
    , "prime2":
        (integer(
            150619677884468353208058156632953891431975271416620955614548039937246769610622017033385394658879484186852231469238992217246264205570458379437126692055331206248530723117202131739966737760399755490935589223401123762051823602343810554978803032803606907761937587101969193241921351011430750970746500680609001799529),
         integer(
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
NASEMP = GVT + XYZCorp

issuerId1 = 111
issuerId2 = 112

iA1 = 100
iA2 = 101

proverId1 = 222
proverId2 = 333

verifierId1 = 555

L = 5


############ module scope

@pytest.fixture(scope="module")
def primes1():
    P_PRIME1, Q_PRIME1 = primes.get("prime1")
    return dict(p_prime=P_PRIME1, q_prime=Q_PRIME1)


@pytest.fixture(scope="module")
def primes2():
    P_PRIME2, Q_PRIME2 = primes.get("prime2")
    return dict(p_prime=P_PRIME2, q_prime=Q_PRIME2)


@pytest.fixture(scope="module")
def keysGvt(primes1):
    return Issuer.genKeys(GVT.attribNames(), **primes1)


@pytest.fixture(scope="module")
def keysXyz(primes2):
    return Issuer.genKeys(XYZCorp.attribNames(), **primes2)


@pytest.fixture(scope="module")
def revocKeysGvt():
    return Issuer.genRevocationKeys()


@pytest.fixture(scope="module")
def revocKeysXyz():
    return Issuer.genRevocationKeys()


@pytest.fixture(scope="module")
def issueAccumulatorGvt(revocKeysGvt):
    return Issuer.issueAccumulator(iA1, revocKeysGvt[0], L)


@pytest.fixture(scope="module")
def issueAccumulatorXyz(revocKeysXyz):
    return Issuer.issueAccumulator(iA2, revocKeysXyz[0], L)


@pytest.fixture(scope="module")
def secretDataGvtIssuer(keysGvt, revocKeysGvt, issueAccumulatorGvt):
    return SecretData(keysGvt[0], keysGvt[1],
                      revocKeysGvt[0], revocKeysGvt[1],
                      issueAccumulatorGvt[0], issueAccumulatorGvt[1], issueAccumulatorGvt[2], issueAccumulatorGvt[3])


@pytest.fixture(scope="module")
def secretDataXyzIssuer(keysXyz, revocKeysXyz, issueAccumulatorXyz):
    return SecretData(keysXyz[0], keysXyz[1],
                      revocKeysXyz[0], revocKeysXyz[1],
                      issueAccumulatorXyz[0], issueAccumulatorXyz[1], issueAccumulatorXyz[2], issueAccumulatorXyz[3])


@pytest.fixture(scope="module")
def issuerGvt(secretDataGvtIssuer):
    return Issuer(issuerId1, secretDataGvtIssuer)


@pytest.fixture(scope="module")
def issuerXyz(secretDataXyzIssuer):
    return Issuer(issuerId2, secretDataXyzIssuer)


@pytest.fixture(scope="module")
def m2GvtProver1(issueAccumulatorGvt):
    return Issuer.genContxt(issueAccumulatorGvt[0].iA, proverId1)


@pytest.fixture(scope="module")
def m2GvtProver2(issueAccumulatorGvt):
    return Issuer.genContxt(issueAccumulatorGvt[0].iA, proverId2)


@pytest.fixture(scope="module")
def m2XyzProver1(issueAccumulatorXyz):
    return Issuer.genContxt(issueAccumulatorXyz[0].iA, proverId1)


@pytest.fixture(scope="module")
def m2XyzProver2(issueAccumulatorXyz):
    return Issuer.genContxt(issueAccumulatorXyz[0].iA, proverId2)


@pytest.fixture(scope="module")
def m1Prover1():
    return ProverInitializer.genMasterSecret()


@pytest.fixture(scope="module")
def m1Prover2():
    return ProverInitializer.genMasterSecret()


@pytest.fixture(scope="module")
def publicDataGvtIssuer(secretDataGvtIssuer):
    return PublicData(secretDataGvtIssuer.pk, secretDataGvtIssuer.pkR,
                      secretDataGvtIssuer.accum, secretDataGvtIssuer.g, secretDataGvtIssuer.pkAccum)


@pytest.fixture(scope="module")
def publicDataXyzIssuer(secretDataXyzIssuer):
    return PublicData(secretDataXyzIssuer.pk, secretDataXyzIssuer.pkR,
                      secretDataXyzIssuer.accum, secretDataXyzIssuer.g, secretDataXyzIssuer.pkAccum)


@pytest.fixture(scope="module")
def prover1Initializer(m2GvtProver1, m2XyzProver1, m1Prover1, publicDataGvtIssuer, publicDataXyzIssuer):
    return ProverInitializer(proverId1,
                             {issuerId1: m2GvtProver1, issuerId2: m2XyzProver1},
                             {issuerId1: publicDataGvtIssuer, issuerId2: publicDataXyzIssuer},
                             m1Prover1)


@pytest.fixture(scope="module")
def prover2Initializer(m2GvtProver2, m2XyzProver2, m1Prover2, publicDataGvtIssuer, publicDataXyzIssuer):
    return ProverInitializer(proverId2,
                             {issuerId1: m2GvtProver2, issuerId2: m2XyzProver2},
                             {issuerId1: publicDataGvtIssuer, issuerId2: publicDataXyzIssuer},
                             m1Prover2)


@pytest.fixture(scope="module")
def prover1UGvt(prover1Initializer):
    return prover1Initializer.getU(issuerId1), prover1Initializer.getUr(issuerId1)


@pytest.fixture(scope="module")
def prover1UXyz(prover1Initializer):
    return prover1Initializer.getU(issuerId2), prover1Initializer.getUr(issuerId2)


@pytest.fixture(scope="module")
def prover2UGvt(prover2Initializer):
    return prover2Initializer.getU(issuerId1), prover2Initializer.getUr(issuerId1)


@pytest.fixture(scope="module")
def prover2UXyz(prover2Initializer):
    return prover2Initializer.getU(issuerId2), prover2Initializer.getUr(issuerId2)


@pytest.fixture(scope="module")
def attrsProver1Gvt(issuerGvt):
    attrs = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    return issuerGvt.encodeAttrs(attrs)


@pytest.fixture(scope="module")
def attrsProver2Gvt(issuerGvt):
    attrs = GVT.attribs(name='Jason', age=42, height=180, sex='male')
    return issuerGvt.encodeAttrs(attrs)


@pytest.fixture(scope="module")
def attrsProver1Xyz(issuerXyz):
    attrs = XYZCorp.attribs(status='partial', period=8)
    return issuerXyz.encodeAttrs(attrs)


@pytest.fixture(scope="module")
def attrsProver2Xyz(issuerXyz):
    attrs = XYZCorp.attribs(status='full-time', period=22)
    return issuerXyz.encodeAttrs(attrs)


@pytest.fixture(scope="module")
def primaryClaimProver1Gvt(issuerGvt, attrsProver1Gvt, m2GvtProver1, prover1UGvt):
    return issuerGvt.issuePrimaryClaim(attrsProver1Gvt, m2GvtProver1, prover1UGvt[0])


@pytest.fixture(scope="module")
def primaryClaimProver2Gvt(issuerGvt, attrsProver2Gvt, m2GvtProver2, prover2UGvt):
    return issuerGvt.issuePrimaryClaim(attrsProver2Gvt, m2GvtProver2, prover2UGvt[0])


@pytest.fixture(scope="module")
def primaryClaimProver1Xyz(issuerXyz, attrsProver1Xyz, m2XyzProver1, prover1UXyz):
    return issuerXyz.issuePrimaryClaim(attrsProver1Xyz, m2XyzProver1, prover1UXyz[0])


@pytest.fixture(scope="module")
def primaryClaimProver2Xyz(issuerXyz, attrsProver2Xyz, m2XyzProver2, prover2UXyz):
    return issuerXyz.issuePrimaryClaim(attrsProver2Xyz, m2XyzProver2, prover2UXyz[0])


@pytest.fixture(scope="module")
def nonRevocClaimProver1Gvt(issuerGvt, m2GvtProver1, prover1UGvt):
    return issuerGvt.issueNonRevocationClaim(m2GvtProver1, prover1UGvt[1])


@pytest.fixture(scope="module")
def nonRevocClaimProver2Gvt(issuerGvt, m2GvtProver2, prover2UGvt):
    return issuerGvt.issueNonRevocationClaim(m2GvtProver2, prover2UGvt[1])


@pytest.fixture(scope="module")
def nonRevocClaimProver1Xyz(issuerXyz, m2XyzProver1, prover1UXyz):
    return issuerXyz.issueNonRevocationClaim(m2XyzProver1, prover1UXyz[1])


@pytest.fixture(scope="module")
def nonRevocClaimProver2Xyz(issuerXyz, m2XyzProver2, prover2UXyz):
    return issuerXyz.issueNonRevocationClaim(m2XyzProver2, prover2UXyz[1])


@pytest.fixture(scope="module")
def initPrimaryClaimProver1Gvt(prover1Initializer, primaryClaimProver1Gvt):
    return prover1Initializer.initPrimaryClaim(issuerId1, primaryClaimProver1Gvt)


@pytest.fixture(scope="module")
def initPrimaryClaimProver1Xyz(prover1Initializer, primaryClaimProver1Xyz):
    return prover1Initializer.initPrimaryClaim(issuerId2, primaryClaimProver1Xyz)


@pytest.fixture(scope="module")
def initPrimaryClaimProver2Gvt(prover2Initializer, primaryClaimProver2Gvt):
    return prover2Initializer.initPrimaryClaim(issuerId1, primaryClaimProver2Gvt)


@pytest.fixture(scope="module")
def initPrimaryClaimProver2Xyz(prover2Initializer, primaryClaimProver2Xyz):
    return prover2Initializer.initPrimaryClaim(issuerId2, primaryClaimProver2Xyz)


@pytest.fixture(scope="module")
def initNonRevocClaimProver1Gvt(prover1Initializer, nonRevocClaimProver1Gvt):
    return prover1Initializer.initNonRevocationClaim(issuerId1, nonRevocClaimProver1Gvt)


@pytest.fixture(scope="module")
def initNonRevocClaimProver1Xyz(prover1Initializer, nonRevocClaimProver1Xyz):
    return prover1Initializer.initNonRevocationClaim(issuerId2, nonRevocClaimProver1Xyz)


@pytest.fixture(scope="module")
def initNonRevocClaimProver2Gvt(prover2Initializer, nonRevocClaimProver2Gvt):
    return prover2Initializer.initNonRevocationClaim(issuerId1, nonRevocClaimProver2Gvt)


@pytest.fixture(scope="module")
def initNonRevocClaimProver2Xyz(prover2Initializer, nonRevocClaimProver2Xyz):
    return prover2Initializer.initNonRevocationClaim(issuerId2, nonRevocClaimProver2Xyz)


@pytest.fixture(scope="module")
def allClaimsProver1(initPrimaryClaimProver1Gvt, initPrimaryClaimProver1Xyz,
                     initNonRevocClaimProver1Gvt, initNonRevocClaimProver1Xyz):
    return {issuerId1: Claims(initPrimaryClaimProver1Gvt, initNonRevocClaimProver1Gvt),
            issuerId2: Claims(initPrimaryClaimProver1Xyz, initNonRevocClaimProver1Xyz)}


@pytest.fixture(scope="module")
def allClaimsProver2(initPrimaryClaimProver2Gvt, initPrimaryClaimProver2Xyz,
                     initNonRevocClaimProver2Gvt, initNonRevocClaimProver2Xyz):
    return {issuerId1: Claims(initPrimaryClaimProver2Gvt, initNonRevocClaimProver2Gvt),
            issuerId2: Claims(initPrimaryClaimProver2Xyz, initNonRevocClaimProver2Xyz)}


@pytest.fixture(scope="module")
def prover1(publicDataGvtIssuer, publicDataXyzIssuer, m1Prover1):
    return Prover(proverId1,
                  {issuerId1: publicDataGvtIssuer, issuerId2: publicDataXyzIssuer},
                  m1Prover1)


@pytest.fixture(scope="module")
def prover2(publicDataGvtIssuer, publicDataXyzIssuer, m1Prover2):
    return Prover(proverId2,
                  {issuerId1: publicDataGvtIssuer, issuerId2: publicDataXyzIssuer},
                  m1Prover2)


@pytest.fixture(scope="module")
def nonce():
    return Verifier.generateNonce()


@pytest.fixture(scope="function")
def genNonce():
    return Verifier.generateNonce()


@pytest.fixture(scope="module")
def verifier(publicDataGvtIssuer, publicDataXyzIssuer):
    return Verifier(verifierId1,
                    {issuerId1: publicDataGvtIssuer, issuerId2: publicDataXyzIssuer})


############ function scope

@pytest.fixture(scope="function")
def newIssueAccumulatorGvt(revocKeysGvt):
    return Issuer.issueAccumulator(iA1, revocKeysGvt[0], L)


@pytest.fixture(scope="function")
def newSecretDataGvtIssuer(keysGvt, revocKeysGvt, newIssueAccumulatorGvt):
    return SecretData(keysGvt[0], keysGvt[1],
                      revocKeysGvt[0], revocKeysGvt[1],
                      newIssueAccumulatorGvt[0], newIssueAccumulatorGvt[1], newIssueAccumulatorGvt[2],
                      newIssueAccumulatorGvt[3])


@pytest.fixture(scope="function")
def newPublicDataGvtIssuer(newSecretDataGvtIssuer):
    return PublicData(newSecretDataGvtIssuer.pk, newSecretDataGvtIssuer.pkR,
                      newSecretDataGvtIssuer.accum, newSecretDataGvtIssuer.g, newSecretDataGvtIssuer.pkAccum)


@pytest.fixture(scope="function")
def newIssuerGvt(newSecretDataGvtIssuer):
    return Issuer(issuerId1, newSecretDataGvtIssuer)


@pytest.fixture(scope="function")
def newM2GvtProver1(newIssueAccumulatorGvt):
    return Issuer.genContxt(newIssueAccumulatorGvt[0].iA, proverId1)


@pytest.fixture(scope="function")
def newProver1Initializer(newM2GvtProver1, m1Prover1, newPublicDataGvtIssuer):
    return ProverInitializer(proverId1,
                             {issuerId1: newM2GvtProver1},
                             {issuerId1: newPublicDataGvtIssuer},
                             m1Prover1)


@pytest.fixture(scope="function")
def newProver1UGvt(newProver1Initializer):
    return newProver1Initializer.getU(issuerId1), newProver1Initializer.getUr(issuerId1)


@pytest.fixture(scope="function")
def newNonRevocClaimProver1Gvt(newIssuerGvt, newM2GvtProver1, newProver1UGvt):
    return newIssuerGvt.issueNonRevocationClaim(newM2GvtProver1, newProver1UGvt[1])


@pytest.fixture(scope="function")
def newInitNonRevocClaimProver1Gvt(newProver1Initializer, newNonRevocClaimProver1Gvt):
    return newProver1Initializer.initNonRevocationClaim(issuerId1, newNonRevocClaimProver1Gvt)


@pytest.fixture(scope="function")
def newProver1(newPublicDataGvtIssuer, m1Prover1):
    return Prover(proverId1,
                  {issuerId1: newPublicDataGvtIssuer},
                  m1Prover1)
