from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.types import GVT
from anoncreds.protocol.verifier import Verifier
from anoncreds.test.helper import getPresentationToken, getProver


def testPredicate():
    attrNames = 'name', 'age', 'sex'
    issuer = Issuer(attrNames)
    issuerPk = {"gvt": issuer.PK}
    verifier = Verifier(pk_i=issuerPk)

    attribs = GVT.attribs(name='Aditya Pratap Singh',
                          age=25,
                          sex='male')

    encodedAttrs = attribs.encoded()
    prover, attrs = getProver(attribs, issuerPk)

    presentationToken = getPresentationToken({"gvt": issuer}, prover, encodedAttrs)

    nonce = verifier.Nonce

    revealedAttrs = ['name']
    predicate = {'gvt': {'age': 18}}
    proof = prover.preparePredicateProof(credential=presentationToken,
                                         attrs=encodedAttrs,
                                         revealedAttrs=revealedAttrs,
                                         nonce=nonce,
                                         predicate=predicate)

    verify_status = verifier.verifyPredicateProof(proof=proof,
                                                  nonce=nonce,
                                                  attrs=encodedAttrs,
                                                  revealedAttrs=revealedAttrs,
                                                  predicate=predicate)

    assert verify_status
