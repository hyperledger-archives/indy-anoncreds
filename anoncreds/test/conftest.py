import pytest

from config.config import cmod

from anoncreds.protocol.attribute_repo import InMemoryAttrRepo
from anoncreds.protocol.cred_def_secret_key import CredDefSecretKey
from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.credential_definition import CredentialDefinition
from anoncreds.protocol.issuer_secret_key import IssuerSecretKey
from anoncreds.protocol.types import AttribDef, AttribType
from anoncreds.protocol.verifier import Verifier
from anoncreds.test.cred_def_test_store import MemoryCredDefStore
from anoncreds.test.helper import getProofBuilderAndAttribs
from anoncreds.test.issuer_key_test_store import MemoryIssuerKeyStore

GVT = AttribDef('gvt',
                [AttribType('name', encode=True),
                 AttribType('age', encode=False),
                 AttribType('sex', encode=True)])
XYZCorp = AttribDef('xyz',
                    [AttribType('status', encode=True)])
NASEMP = GVT + XYZCorp

@pytest.fixture(scope="module")
def gvtAttrRepo():
    attrRepo = InMemoryAttrRepo()
    attrRepo.addAttributes('prover1', GVT.attribs())
    return attrRepo


@pytest.fixture(scope="module")
def gvt(gvtAttrRepo):
    return Issuer(GVT.name, gvtAttrRepo)


@pytest.fixture(scope="module")
def gvtAttrNames():
    return GVT.attribNames()


@pytest.fixture(scope="module")
def xyzAttrNames():
    return XYZCorp.attribNames()


@pytest.fixture(scope="module")
def gvtCredDefId():
    return 578


@pytest.fixture(scope="module")
def gvtCredDef(gvtCredDefId, gvtAttrNames):
    return CredentialDefinition(gvtCredDefId, gvtAttrNames)


@pytest.fixture(scope="module")
def gvtIssuerSecretKey(gvtCredDef, gvtSecretKey):
    return IssuerSecretKey(cd=gvtCredDef, sk=gvtSecretKey)


@pytest.fixture(scope="module")
def xyzCredDefId():
    return 8165867


@pytest.fixture(scope="module")
def xyzCredDef(xyzCredDefId, xyzAttrNames):
    return CredentialDefinition(xyzCredDefId, xyzAttrNames)


@pytest.fixture(scope="module")
def xyzIssuerSecretKey(xyzCredDef, xyzSecretKey):
    return IssuerSecretKey(cd=xyzCredDef, sk=xyzSecretKey)


@pytest.fixture(scope="module")
def gvtCredDefPks(gvtIssuerSecretKey):
    return {GVT.name: gvtIssuerSecretKey.PK}


@pytest.fixture(scope="module")
def xyzCredDefPks(xyzIssuerSecretKey):
    return {XYZCorp.name: xyzIssuerSecretKey.PK}


@pytest.fixture(scope="module")
def gvtAndXyzCredDefs(gvtCredDef, xyzCredDef):
    return {GVT.name: gvtCredDef,
            XYZCorp.name: xyzCredDef}


@pytest.fixture(scope="module")
def gvtAndXyzCredDefPks(gvtCredDefPks, xyzCredDefPks):
    _ = {}
    _.update(gvtCredDefPks)
    _.update(xyzCredDefPks)
    return _


@pytest.fixture(scope="module")
def gvtAndXyzIssuerSecretKeys(gvtIssuerSecretKey, xyzIssuerSecretKey):
    return {GVT.name: gvtIssuerSecretKey,
            XYZCorp.name: xyzIssuerSecretKey}


@pytest.fixture(scope="module")
def staticPrimes():
    return {
        "prime1": (
            cmod.integer(157329491389375793912190594961134932804032426403110797476730107804356484516061051345332763141806005838436304922612495876180233509449197495032194146432047460167589034147716097417880503952139805241591622353828629383332869425029086898452227895418829799945650973848983901459733426212735979668835984691928193677469),
            cmod.integer(151323892648373196579515752826519683836764873607632072057591837216698622729557534035138587276594156320800768525825023728398410073692081011811496168877166664537052088207068061172594879398773872352920912390983199416927388688319207946493810449203702100559271439586753256728900713990097168484829574000438573295723)
        ),
        "prime2": (
            cmod.integer(150619677884468353208058156632953891431975271416620955614548039937246769610622017033385394658879484186852231469238992217246264205570458379437126692055331206248530723117202131739966737760399755490935589223401123762051823602343810554978803032803606907761937587101969193241921351011430750970746500680609001799529),
            cmod.integer(171590857568436644992359347719703764048501078398666061921719064395827496970696879481740311141148273607392657321103691543916274965279072000206208571551864201305434022165176563363954921183576230072812635744629337290242954699427160362586102068962285076213200828451838142959637006048439307273563604553818326766703)
        )}


@pytest.fixture(scope="module")
def gvtSecretKey(staticPrimes):
    return CredDefSecretKey(*staticPrimes.get("prime1"))


@pytest.fixture(scope="module")
def xyzSecretKey(staticPrimes):
    return CredDefSecretKey(*staticPrimes.get("prime2"))


@pytest.fixture(scope="module")
def gvtAttrList():
    return GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male')


@pytest.fixture(scope="module")
def xyzAttrList():
    return XYZCorp.attribs(status='ACTIVE')


# @pytest.fixture(scope="module")
# def credDefPk(gvtCredDef):
#     """Return gvtCredDef's public key"""
#
#     return {GVT.name: gvtCredDef.PK}


@pytest.fixture(scope="module")
def gvtProofBuilderWithProver1(gvtCredDefPks):
    attribs = GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male')
    return getProofBuilderAndAttribs(attribs, gvtCredDefPks)


@pytest.fixture(scope="module")
def gvtProofBuilderWithProver2(gvtCredDefPks):
    attribs = GVT.attribs(name='Jason Law', age=42, sex='male')
    return getProofBuilderAndAttribs(attribs, gvtCredDefPks)


@pytest.fixture(scope="module")
def proofBuilderWithGvtAttribs(gvtCredDefPks):
    attribs = GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male')
    return getProofBuilderAndAttribs(attribs, gvtCredDefPks)


@pytest.fixture(scope="module")
def proofBuilderWithXyzAttribs(xyzCredDefPks):
    attribs = XYZCorp.attribs(status='ACTIVE')
    return getProofBuilderAndAttribs(attribs, xyzCredDefPks)


@pytest.fixture(scope="module")
def proofBuilderWithGvtAndXyzAttribs(gvtAndXyzCredDefPks, gvtAttrList, xyzAttrList):
    attributeList = gvtAttrList + xyzAttrList
    return getProofBuilderAndAttribs(attributeList, gvtAndXyzCredDefPks)


@pytest.fixture(scope="module")
def credDefStore():
    return MemoryCredDefStore()


@pytest.fixture(scope="module")
def issuerKeyStore():
    return MemoryIssuerKeyStore()


@pytest.fixture(scope="module")
def verifier1(credDefStore, issuerKeyStore):
    return Verifier('verifier1',
                    credDefStore=credDefStore,
                    issuerKeyStore=issuerKeyStore)


@pytest.fixture(scope="module")
def verifierMulti1(credDefStore, issuerKeyStore):
    return Verifier('verifierMulti1',
                    credDefStore=credDefStore,
                    issuerKeyStore=issuerKeyStore)


@pytest.fixture(scope="module")
def verifierMulti2(credDefStore, issuerKeyStore):
    return Verifier('verifierMulti2',
                    credDefStore=credDefStore,
                    issuerKeyStore=issuerKeyStore)

