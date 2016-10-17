import pytest


def run():
    runs = 40
    fails = 0
    for x in range(runs):
        itr = x + 1
        print('running {}'.format(itr))
        d = dict(
            module='test_multiple_credentials_locked',
            tname='testMultiCredSingleProof')
        result = pytest.main('-x {module}.py::{tname}'.format(**d))
        failed = bool(result)
        fails += int(failed)
    print("{} runs, {} failures".format(runs, fails))

if __name__ == '__main__':
    run()
