from anoncreds.test.helper import getProver, getPresentationToken
from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.verifier import Verifier


attrNames = 'name', 'age', 'sex'
issuer = Issuer(attrNames)
issuerPk = {GVT.name: issuer.PK}
verifier = Verifier(pk_i=issuerPk)

attr_vals = {'name': 'Aditya Pratap Singh', 'age': 25, 'sex': 'male'}
prover, encodedAttrs, attrs = getProver(attr_vals, issuerPk)
encodedAttrsDict = {GVT.name: encodedAttrs}

presentationToken = getPresentationToken({GVT.name: issuer}, prover, encodedAttrsDict)

nonce = verifier.generateNonce

revealedAttrs = ['name']
predicate = {GVT.name: {'age': 18}}
proof = prover.preparePredicateProof(credential=presentationToken, attrs=encodedAttrs,
                                     revealedAttrs=revealedAttrs, nonce=nonce,
                                     predicate=predicate, encodedAttrsDict=encodedAttrsDict)

verify_status = verifier.verifyPredicateProof(proof=proof, nonce=nonce,
                                      attrs=encodedAttrs, revealedAttrs=revealedAttrs,
                                      predicate=predicate, encodedAttrsDict=encodedAttrsDict)

if verify_status:
    print("Proof verified")
else:
    print("Proof not valid")