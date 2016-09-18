import pytest

from anoncreds.test.conftest import GVT
from anoncreds.test.conftest import XYZCorp
from anoncreds.test.helper import verifyPredicateGreaterEq


def testPredicateGreaterEq(gvtIssuer, prover, verifier, attrRepo, primes1):
    attrRepo.addAttributes(prover.id, gvtIssuer.id,
                           GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male'))

    predicate = {GVT.name: {'age': 18}}
    assert verifyPredicateGreaterEq(attrRepo,  ['name'], [gvtIssuer], prover, [verifier], primes1, predicate)


def testPredicateEqHolds(gvtIssuer, prover, verifier, attrRepo, primes1):
    attrRepo.addAttributes(prover.id, gvtIssuer.id,
                           GVT.attribs(name='Aditya Pratap Singh', age=18, sex='male'))

    predicate = {GVT.name: {'age': 18}}
    assert verifyPredicateGreaterEq(attrRepo,  ['name'], [gvtIssuer], prover, [verifier], primes1, predicate)


def testPredicateGreaterEqMultiIssuers(attrRepo, gvtIssuer, xyzIssuer, prover, verifier, primes1):
    attrRepo.addAttributes(prover.id, gvtIssuer.id,
                           GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male'))
    attrRepo.addAttributes(prover.id, xyzIssuer.id,
                           XYZCorp.attribs(status='ACTIVE'))

    predicate = {GVT.name: {'age': 18}}
    assert verifyPredicateGreaterEq(attrRepo,  ['name'], [gvtIssuer, xyzIssuer], prover, [verifier], primes1, predicate)


def testPredicateGreaterEqNegativeDelta(attrRepo, gvtIssuer, xyzIssuer, prover, verifier, primes1):
    attrRepo.addAttributes(prover.id, gvtIssuer.id,
                           GVT.attribs(name='Aditya Pratap Singh', age=17, sex='male'))
    attrRepo.addAttributes(prover.id, xyzIssuer.id,
                           XYZCorp.attribs(status='ACTIVE'))

    predicate = {GVT.name: {'age': 18}}
    with pytest.raises(ValueError):
        assert verifyPredicateGreaterEq(attrRepo,  ['name'], [gvtIssuer, xyzIssuer], prover, [verifier], primes1, predicate)


def testPredicateGreaterEqMultipleProvers(attrRepo, gvtIssuer, prover, prover2, verifier, primes1):
    attrRepo.addAttributes(prover.id, gvtIssuer.id,
                           GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male'))
    attrRepo.addAttributes(prover2.id, gvtIssuer.id,
                           GVT.attribs(name='Aditya Pratap Singh', age=35, sex='male'))

    predicate = {GVT.name: {'age': 30}}
    assert verifyPredicateGreaterEq(attrRepo,  ['name'], [gvtIssuer], prover2, [verifier], primes1, predicate)

    predicate = {GVT.name: {'age': 20}}
    assert verifyPredicateGreaterEq(attrRepo, ['name'], [gvtIssuer], prover, [verifier], primes1, predicate)

    predicate = {GVT.name: {'age': 40}}
    with pytest.raises(ValueError):
        assert verifyPredicateGreaterEq(attrRepo, ['name'], [gvtIssuer], prover2, [verifier], primes1, predicate)

    predicate = {GVT.name: {'age': 30}}
    with pytest.raises(ValueError):
        assert verifyPredicateGreaterEq(attrRepo, ['name'], [gvtIssuer], prover, [verifier], primes1, predicate)
