import uuid

import pytest

from anoncreds.protocol.proof_builder import ProofBuilder
from anoncreds.protocol.prover import Prover
from anoncreds.test.cred_def_test_store import MemoryCredDefStore
from anoncreds.test.issuer_key_test_store import MemoryIssuerKeyStore


@pytest.fixture(scope="module")
def prover(gvtCredDef, gvtIssuerPk):
    uid = str(uuid.uuid4())
    mcds = MemoryCredDefStore()
    mcds.publishCredDef(gvtCredDef)
    miks = MemoryIssuerKeyStore()
    for ipk in gvtIssuerPk.values():
        miks.publishIssuerKey(ipk)
    return Prover(id=uid, cds=mcds, iks=miks)


def testProverHasMasterSecret(prover):
    assert prover.masterSecret


def testProofBuilderDoesNotGenerateMasterSecret(prover, gvtIssuerPk):
    with pytest.raises(TypeError):
        ProofBuilder(gvtIssuerPk)


def testProofBuilderDoesNotGenerateVPrime(prover, gvtIssuerPk):
    with pytest.raises(TypeError):
        ProofBuilder(gvtIssuerPk, prover.masterSecret)


@pytest.fixture(scope="module")
def proverGeneratesVPrime(prover, gvtIssuerPk):
    key = next(iter(gvtIssuerPk.keys()))
    assert key not in prover._vprimes
    assert prover.getVPrimes(key)
    assert key in prover._vprimes
    return prover


def testProverHasVPrimeLazily(proverGeneratesVPrime):
    pass


def testProofBuilderCreated(gvtIssuerPk, proverGeneratesVPrime):
    prover = proverGeneratesVPrime
    key = next(iter(gvtIssuerPk.keys()))
    pb = ProofBuilder(gvtIssuerPk, prover.masterSecret, prover.getVPrimes(key))
    assert pb
