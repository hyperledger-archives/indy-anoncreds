from anoncreds.protocol.types import GVT, XYZCorp
from anoncreds.protocol.credential_definition import CredentialDefinition
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


def testPredicateMultipleIssuers(issuers, proverAndAttrsForMultiple1,
                                 proverAndAttrsForMultiple2,
                                 verifierMulti1):
    attrNames1 = 'name', 'age', 'sex'
    issuer1 = CredentialDefinition(attrNames1)
    attrNames2 = 'status',
    issuer2 = CredentialDefinition(attrNames2)

    issuersPK = {GVT.name: issuer1.PK, "xyz": issuer2.PK}

    attrs1 = GVT.attribs(name='Aditya Pratap Singh',
                          age=25,
                          sex='male')

    attrs2 = XYZCorp.attribs(status='ACTIVE')

    attribs = attrs1 + attrs2

    prover, attrs = getProver(attribs, issuersPK)

    presentationToken = getPresentationToken(issuers, prover, attrs.encoded())

    nonce = verifierMulti1.Nonce

    revealedAttrs = ['name']
    predicate = {GVT.name: {'age': 18}}
    proof = prover.preparePredicateProof(credential=presentationToken, attrs=attrs.encoded(),
                                         revealedAttrs=revealedAttrs, nonce=nonce,
                                         predicate=predicate)

    verify_status = verifierMulti1.verifyPredicateProof(proof=proof, nonce=nonce, attrs=attrs.encoded(),
                                                        revealedAttrs=revealedAttrs, predicate=predicate)

    assert verify_status