import pytest


def run():
    for x in range(100):
        itr = x + 1
        print('running {}'.format(itr))
        pytest.main('-x')
        # pytest.main('-x test_greater_eq_predicate.py::testPredicateMultipleIssuers')

if __name__ == '__main__':
    run()
