from anoncreds.test.helper import getProver, getPresentationToken
from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.verifier import Verifier


attrNames = 'name', 'age', 'sex'
issuer = Issuer(attrNames)
issuerPk = {"gvt": issuer.PK}
verifier = Verifier(pk_i=issuerPk)

prover, encodedAttrs, attrs = getProver({'name': 'Aditya Pratap Singh', 'age': 25, 'sex': 'male'}, issuerPk)
encodedAttrsDict = {"gvt": encodedAttrs}

presentationToken = getPresentationToken({"gvt": issuer}, prover, encodedAttrsDict)

nonce = verifier.Nonce

revealedAttrs = ['name']
predicate = {'gvt': {'age': 18}}
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