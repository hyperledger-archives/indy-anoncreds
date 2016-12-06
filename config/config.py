import glob
import importlib
import os
import re


def dynamicModule():
    pkg = os.path.dirname(os.path.realpath(__file__))
    clib_pattern = os.path.join(pkg, '**', 'config-crypto-*.py')
    clibs = [fn for fn in glob.glob(clib_pattern, recursive=True)]

    if len(clibs) == 0:
        raise RuntimeError('A crypto-lib must exist for anoncreds to run.')
    elif len(clibs) > 1:
        print('Found more than one crypto library, picking the first one...')
    print('Loading module {}'.format(clibs[0]))

    m = re.match('.*(config-crypto-.*)\.py', clibs[0]).groups()[0]

    mod = importlib.import_module('config.' + m)
    print('Module loaded.')
    return mod


cmod = dynamicModule()
