from anoncreds.test.conftest import GVT
from anoncreds.test.helper import verifyEquality


def testSingleProver(gvtIssuer, prover, verifier, gvtAttrRepo, primes1):
    assert verifyEquality(gvtAttrRepo,  ['name'], [gvtIssuer], prover, [verifier], primes1)


def testMultipleProvers(gvtIssuer, prover, prover2, verifier, attrRepo, primes1):
    attrRepo.addAttributes(prover.id, gvtIssuer.id,
                           GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male'))
    attrRepo.addAttributes(prover2.id, gvtIssuer.id,
                           GVT.attribs(name='Jason Law', age=42, sex='male'))

    assert verifyEquality(attrRepo,  ['name'], [gvtIssuer], prover, [verifier], primes1)

    assert verifyEquality(attrRepo,  ['name'], [gvtIssuer], prover2, [verifier], primes1)


def testNonceShouldBeSame(gvtIssuer, prover, verifier, gvtAttrRepo, primes1, genNonce):
    assert not verifyEquality(gvtAttrRepo,  ['name'], [gvtIssuer], prover, [verifier], primes1, defaultNonce=genNonce)


def testUParamShouldBeCorrect(gvtIssuer, prover, verifier, gvtAttrRepo, primes1):
    assert not verifyEquality(gvtAttrRepo,  ['name'], [gvtIssuer], prover, [verifier], primes1, defaultU=1)

