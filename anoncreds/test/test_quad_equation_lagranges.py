import pytest

from anoncreds.protocol.primary.primary_proof_builder import fourSquares


def testQuadEquationLagranges():
    delta = 85
    u = fourSquares(delta)
    print("u1: {0} u2: {1} u3: {2} u4: {3}".format(u['0'], u['1'], u['2'],
                                                   u['3']))
    assert (u['0'] ** 2) + (u['1'] ** 2) + (u['2'] ** 2) + (
        u['3'] ** 2) == delta


def testQuadEquationLagrangesNegativeInt():
    delta = -5
    with pytest.raises(ValueError):
        u = fourSquares(delta)
