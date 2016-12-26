import pytest


def run():
    runs = 40
    fails = 0
    for x in range(runs):
        itr = x + 1
        print('running {}'.format(itr))
        # tst = 'test_greater_eq_predicate.py::testPredicateGreaterEqMultiIssuers'
        # result = pytest.main('-x --tb=long -n 7 {}'.format(tst))
        result = pytest.main('-x')
        failed = bool(result)
        fails += int(failed)
    print("{} runs, {} failures".format(runs, fails))


if __name__ == '__main__':
    run()
