import pytest

from anoncreds.protocol.types import Attribs
from anoncreds.test.conftest import GVT, XYZCorp


def testEmpty(prover1, allClaims, attrRepo):
    revealedAttrs = attrRepo.getRevealedAttributesForProver(prover1, [])
    assert Attribs() == revealedAttrs


def testOneFromOneClaimDef(prover1, allClaims, attrRepo, attrsProver1Gvt):
    revealedAttrs = attrRepo.getRevealedAttributesForProver(prover1, ['name'])
    expected = Attribs(GVT,
                       **{'name': attrsProver1Gvt['name']})
    assert expected == revealedAttrs


def testTwoFromOneClaimDef(prover1, allClaims, attrRepo, attrsProver1Gvt):
    revealedAttrs = attrRepo.getRevealedAttributesForProver(prover1, ['name', 'age'])
    expected = Attribs(GVT,
                       **{'name': attrsProver1Gvt['name'],
                          'age': attrsProver1Gvt['age']})
    assert expected == revealedAttrs


def testOneFromTwoClaimDef(prover1, allClaims, attrRepo, attrsProver1Gvt, attrsProver1Xyz):
    revealedAttrs = attrRepo.getRevealedAttributesForProver(prover1, ['name', 'status'])
    expected = Attribs(GVT + XYZCorp,
                       **{'name': attrsProver1Gvt['name'],
                          'status': attrsProver1Xyz['status']})
    assert expected == revealedAttrs


def testTwoFromTwoClaimDef(prover1, allClaims, attrRepo, attrsProver1Gvt, attrsProver1Xyz):
    revealedAttrs = attrRepo.getRevealedAttributesForProver(prover1, ['name', 'age', 'status', 'period'])
    expected = Attribs(GVT + XYZCorp,
                       **{'name': attrsProver1Gvt['name'],
                          'age': attrsProver1Gvt['age'],
                          'status': attrsProver1Xyz['status'],
                          'period': attrsProver1Xyz['period']})
    assert expected == revealedAttrs


def testUnknownAttribute(prover1, allClaims, attrRepo):
    with pytest.raises(ValueError):
        attrRepo.getRevealedAttributesForProver(prover1, ['aaa'])


def testNotAllAttrsFound(prover1, allClaims, attrRepo):
    with pytest.raises(ValueError):
        attrRepo.getRevealedAttributesForProver(prover1, ['name', 'aaa'])


def testNoClaimForAttr(prover1, claimsProver2Gvt, attrRepo):
    with pytest.raises(ValueError):
        attrRepo.getRevealedAttributesForProver(prover1, ['name'])
