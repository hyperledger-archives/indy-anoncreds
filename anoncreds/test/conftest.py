import uuid

import pytest

from anoncreds.protocol.issuer_key import IssuerKey
from anoncreds.protocol.prover import Prover
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


# @pytest.fixture(scope="module")
# def gvt(gvtAttrRepo):
#     return Issuer(GVT.name, gvtAttrRepo)


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
def xyzIssuerSecretKey(xyzCredDef, xyzSecretKey, tiedown):
    if tiedown is True:
        N = xyzSecretKey.n
        R = {'status': 16163990731050740363904875830118412059924099387981998475996138832084672783466211342514418108802852231950000663331971024093354494570772463754244091172896559485931403485480707853136661025870769410788749140277776168917641720142345372901078004037550701622192874822035412217011417560439155279537635863149885700418839251260341614599377297764910596008314485297273697379753563185127379736982271413589284242827009578806038653271740343203453189010565712896291520672533957352312540846648557993980064876546646493880558674605126637793271329379816683021568174723660803015323913369565720953421056747876954938777237159413064558426134,
             '0': 6718121851512541505278457499949740199951202608704698944365224359634912192321092467604549824760613958607037426878315815386473492977033093837986867693163318781281736526526770992596597743382226954040728530182824145815030437391474775074299797548148854509174975497956314166837973098598516103519001661695514998388407092378804429823307101168242970096647876943605661781302781669113119290798375578516145236933066572582298412024654263090861876786164671139036271962002708290930683719271405771814412313735588612936245941456852046832465483926257879119217820394551490906651438044538431023319768975449146136965660881592128342545912}
        S = 3343806603215269077555058493430692496276026368424842922706912877607758619981259006335460228028164253603118759063944453448733482885511292397721798012893042472868583332838135200525366536270817513122833452760821609374584402366828236941444105302064759652410538973818049033864501134488925213122687074337540894268301793965464549899811794167095756255041424311121704584119317345385800779563972674095702716578188856179364024984658892215760410445082785542253201507494390766569876226189397855943049212937622291965612182083235735752918020943916807993164971869817500542058908985761039643125169111950615762805353267209657152636063
        Z = 20980283896248112949657908621762844593937360982238535091790322615695193882425300579326866806094426346272003960411744146713540894595280006650190709173348693828003776211049208928602675793015282702581145244330460383549086225328800751356371014114596821682266619800426878665209021126810726360323762445497380361700075528074923306800222274204000498925515121534937411527857884890240819360864772148719945273255660641654453977165376976742564785721638484876370156460267854223342324897984039009343307817325249690093021930047493861429502407408544842701360899039826466513511132833738929137704787726155370023453766117484197735257819
        pubkey = IssuerKey(None, N, R, S, Z)
    else:
        pubkey = None
    isk = IssuerSecretKey(cd=xyzCredDef, sk=xyzSecretKey, pubkey=pubkey)
    return isk


@pytest.fixture(scope="module")
def gvtIssuerPk(gvtIssuerSecretKey):
    return {GVT.name: gvtIssuerSecretKey.PK}


@pytest.fixture(scope="module")
def xyzCredDefPks(xyzIssuerSecretKey):
    return {XYZCorp.name: xyzIssuerSecretKey.PK}


@pytest.fixture(scope="module")
def gvtAndXyzCredDefs(gvtCredDef, xyzCredDef):
    return {GVT.name: gvtCredDef,
            XYZCorp.name: xyzCredDef}


@pytest.fixture(scope="module")
def gvtAndXyzCredDefPks(gvtIssuerPk, xyzCredDefPks):
    _ = {}
    _.update(gvtIssuerPk)
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


@pytest.fixture(scope="module")
def gvtProofBuilderWithProver1(gvtCredDef, gvtIssuerPk):
    attribs = GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male')
    return getProofBuilderAndAttribs(attribs, {GVT.name: gvtCredDef}, gvtIssuerPk)


@pytest.fixture(scope="module")
def gvtProofBuilderWithProver2(gvtCredDef, gvtIssuerPk):
    attribs = GVT.attribs(name='Jason Law', age=42, sex='male')
    return getProofBuilderAndAttribs(attribs, {GVT.name: gvtCredDef}, gvtIssuerPk)


@pytest.fixture(scope="module")
def proofBuilderWithGvtAttribs(gvtCredDef, gvtIssuerPk):
    attribs = GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male')
    return getProofBuilderAndAttribs(attribs, {GVT.name: gvtCredDef}, gvtIssuerPk)


@pytest.fixture(scope="module")
def proofBuilderWithXyzAttribs(xyzCredDef, xyzCredDefPks):
    attribs = XYZCorp.attribs(status='ACTIVE')
    return getProofBuilderAndAttribs(attribs, {XYZCorp.name: xyzCredDef}, xyzCredDefPks)


@pytest.fixture(scope="module")
def proofBuilderWithGvtAndXyzAttribs(gvtAndXyzCredDefs, gvtAndXyzCredDefPks,
                                     gvtAttrList, xyzAttrList):
    attributeList = gvtAttrList + xyzAttrList
    return getProofBuilderAndAttribs(attributeList, gvtAndXyzCredDefs,
                                     gvtAndXyzCredDefPks)


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


@pytest.fixture(scope="module")
def tiedown(request):
    return getValueFromModule(request, "tieDownRandomElements", False)


def getValueFromModule(request, name: str, default=None):
    """
    Gets an attribute from the request's module if attribute is found
    else return the default value

    :param request:
    :param name: name of attribute to get from module
    :param default: value to return if attribute was not found
    :return: value of the attribute if attribute was found in module else the default value
    """
    if hasattr(request.module, name):
        value = getattr(request.module, name)
        print("found {} in the module: {}".format(name, value))
    else:
        value = default if default is not None else None
        print("no {} found in the module, using the default: {}".
              format(name, value))
    return value


