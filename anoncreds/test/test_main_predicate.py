from anoncreds.protocol.types import GVT
from anoncreds.test.helper import getProver, getPresentationToken
from anoncreds.protocol.verifier import Verifier


def testMainPredicate(credDef1):
    credDef = credDef1
    issuerPk = {GVT.name: credDef.PK}
    verifier = Verifier(pk_i=issuerPk)

    attribs = GVT.attribs(name='Aditya Pratap Singh',
                          age=25,
                          sex='male')

    prover, attrs = getProver(attribs.encoded(), issuerPk)

    presentationToken = getPresentationToken({GVT.name: credDef}, prover, attrs)

    nonce = verifier.Nonce

    revealedAttrs = ['name']
    predicate = {GVT.name: {'age': 18}}
    proof = prover.preparePredicateProof(credential=presentationToken,
                                         attrs=attrs,
                                         revealedAttrs=revealedAttrs,
                                         nonce=nonce,
                                         predicate=predicate)

    verify_status = verifier.verifyPredicateProof(proof=proof,
                                                  nonce=nonce,
                                                  attrs=attrs,
                                                  revealedAttrs=revealedAttrs,
                                                  predicate=predicate)

    assert verify_status
