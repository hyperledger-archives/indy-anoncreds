from anoncreds.test.helper import verifyEquality


def testMultipleIssuers(gvtXyzAttrRepo, gvtIssuer, xyzIssuer, prover, verifier, primes1):
    assert verifyEquality(gvtXyzAttrRepo,  ['name'], [gvtIssuer, xyzIssuer], prover, [verifier], primes1)


def testMultiIssuersMultiVerifiers(gvtXyzAttrRepo, gvtIssuer, xyzIssuer, prover, verifier, verifier2, primes1):
    assert verifyEquality(gvtXyzAttrRepo,  ['name'], [gvtIssuer, xyzIssuer], prover, [verifier, verifier2], primes1)

