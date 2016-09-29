import pytest


def run():
    for x in range(1000):
        itr = x + 1
        print('running {}'.format(itr))
        result = pytest.main('-x')
        #tst = 'test_greater_eq_predicate.py::testPredicateGreaterEqMultiIssuers'
        #result = pytest.main('-x --tb=long -n 7 {}'.format(tst))
        if result > 0:
            break


if __name__ == '__main__':
    run()
