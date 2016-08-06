import pytest

from anoncreds.protocol.proof_builder import fourSquares


def testQuadEquationLagranges():
    delta = 85
    u1, u2, u3, u4 = tuple(fourSquares(delta))
    print("u1: {0} u2: {1} u3: {2} u4: {3}".format(u1, u2, u3, u4))
    assert (u1 ** 2) + (u2 ** 2) + (u3 ** 2) + (u4 ** 2) == delta


def testQuadEquationLagrangesNegativeInt():
    delta = -5
    with pytest.raises(ValueError):
        u1, u2, u3, u4 = tuple(fourSquares(delta))