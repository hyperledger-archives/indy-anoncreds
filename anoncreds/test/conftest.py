import pytest
from charm.toolbox.pairinggroup import PairingGroup, G1

from anoncreds.protocol.attribute_repo import InMemoryAttrRepo
from anoncreds.protocol.credential_definition import CredentialDefinitionInternal, primes
from anoncreds.protocol.credential_defs_repo import InMemoryCredentialDefsRepo
from anoncreds.protocol.credential_defs_secret_repo import InMemoryCredentialDefsSecretRepo
from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.prover import Prover
from anoncreds.protocol.revocation.accumulators.accumulator_definition import AccumulatorDefinition
from anoncreds.protocol.revocation.accumulators.issuance_revocation_builder import IssuanceRevocationBuilder
from anoncreds.protocol.revocation.accumulators.proof_revocation_builder import ProofRevocationBuilder
from anoncreds.protocol.revocation.accumulators.proof_revocation_verifier import ProofRevocationVerifier
from anoncreds.protocol.types import AttribDef, AttribType
from anoncreds.protocol.verifier import Verifier

GVT = AttribDef('gvt',
                [AttribType('name', encode=True),
                 AttribType('age', encode=False),
                 AttribType('sex', encode=True)])
XYZCorp = AttribDef('xyz',
                    [AttribType('status', encode=True)])
NASEMP = GVT + XYZCorp

@pytest.fixture(scope="module")
def gvtAttrNames():
    return GVT.attribNames()


@pytest.fixture(scope="module")
def gvtCredDef(gvtAttrNames, primes1):
    return CredentialDefinitionInternal(gvtAttrNames, **primes1)


@pytest.fixture(scope="function")
def attrRepo():
    return InMemoryAttrRepo()


@pytest.fixture(scope="function")
def gvtAttrRepo(attrRepo, gvtIssuer, prover):
    attrRepo.addAttributes(prover.id, gvtIssuer.id,
                           GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male'))
    return attrRepo


@pytest.fixture(scope="function")
def gvtXyzAttrRepo(attrRepo, gvtIssuer, xyzIssuer, prover):
    attrRepo.addAttributes(prover.id, gvtIssuer.id,
                          GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male'))
    attrRepo.addAttributes(prover.id, xyzIssuer.id,
                           XYZCorp.attribs(status='ACTIVE'))
    return attrRepo


@pytest.fixture(scope="function")
def credDefRepo():
    return InMemoryCredentialDefsRepo()


@pytest.fixture(scope="function")
def credDefSecretRepo(credDefRepo):
    return InMemoryCredentialDefsSecretRepo(credDefRepo)


@pytest.fixture(scope="function")
def genNonce(credDefRepo):
    return Verifier("verifierTmp", credDefRepo).nonce


@pytest.fixture(scope="function")
def gvtIssuer(credDefSecretRepo, attrRepo):
    return Issuer(GVT.name, credDefSecretRepo, attrRepo)


@pytest.fixture(scope="function")
def xyzIssuer(credDefSecretRepo, attrRepo):
    return Issuer(XYZCorp.name, credDefSecretRepo, attrRepo)


@pytest.fixture(scope="function")
def xyzIssuer(credDefSecretRepo, attrRepo):
    return Issuer(XYZCorp.name, credDefSecretRepo, attrRepo)


@pytest.fixture(scope="function")
def prover(credDefRepo):
    return Prover("prover1", credDefRepo)


@pytest.fixture(scope="function")
def prover2(credDefRepo):
    return Prover("prover2", credDefRepo)


@pytest.fixture(scope="function")
def verifier(credDefRepo):
    return Verifier("verifier1", credDefRepo)


@pytest.fixture(scope="function")
def verifier2(credDefRepo):
    return Verifier("verifier2", credDefRepo)


@pytest.fixture(scope="module")
def primes1():
    P_PRIME1, Q_PRIME1 = primes.get("prime1")
    return dict(p_prime=P_PRIME1, q_prime=Q_PRIME1)


@pytest.fixture(scope="module")
def primes2():
    P_PRIME2, Q_PRIME2 = primes.get("prime2")
    return dict(p_prime=P_PRIME2, q_prime=Q_PRIME2)


@pytest.fixture(scope="function")
def accumulatorWithAllKeys():
    accDef = AccumulatorDefinition()
    revPk, revSk = accDef.genRevocationKeys()
    acc, g, accSk = accDef.issueAccumulator("accum1", revPk, L=5)
    return (revPk, revSk, acc, g, accSk)


@pytest.fixture(scope="function")
def accumulatorWithKeys(accumulatorWithAllKeys):
    return (accumulatorWithAllKeys[0], accumulatorWithAllKeys[2], accumulatorWithAllKeys[3])


@pytest.fixture(scope="function")
def g(accumulatorWithKeys):
    return accumulatorWithKeys[2]

@pytest.fixture(scope="function")
def issuanceRevBuilder(accumulatorWithAllKeys):
    return IssuanceRevocationBuilder(accumulatorWithAllKeys[0], accumulatorWithAllKeys[1])

@pytest.fixture(scope="function")
def proofRevBuilder(accumulatorWithKeys, gvtIssuer, prover):
    return ProofRevocationBuilder(gvtIssuer.id, accumulatorWithKeys[0], prover._ms)

@pytest.fixture(scope="function")
def proofRevVerifier(accumulatorWithKeys, verifier):
    return ProofRevocationVerifier(accumulatorWithKeys[0], verifier.nonce)

@pytest.fixture(scope="function")
def witnessCredentialsAndAccum(accumulatorWithAllKeys, issuanceRevBuilder, proofRevBuilder):
    revPk, revSk, acc, g, accSk = accumulatorWithAllKeys
    witCred = issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    return (witCred, acc)

@pytest.fixture(scope="function")
def witnessCredentials(accumulatorWithAllKeys, issuanceRevBuilder, proofRevBuilder):
    revPk, revSk, acc, g, accSk = accumulatorWithAllKeys
    return issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)

@pytest.fixture(scope="function")
def witnessCredentialsAndAccumMultiple(accumulatorWithAllKeys, issuanceRevBuilder, proofRevBuilder):
    revPk, revSk, acc, g, accSk = accumulatorWithAllKeys
    issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    witCred = issuanceRevBuilder.issueRevocationCredential(acc, accSk, g, proofRevBuilder.Ur)
    return (witCred, acc)

@pytest.fixture(scope="function")
def genUr(accumulatorWithKeys):
    group = PairingGroup(accumulatorWithKeys[0].groupType)
    return group.random(G1)