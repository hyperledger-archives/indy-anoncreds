from anoncreds.protocol.attribute_repo import InMemoryAttrRepo
from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.prover import Prover
from anoncreds.temp_primes import P_PRIME1, Q_PRIME1
from anoncreds.protocol.verifier import Verifier
from anoncreds.test.conftest import GVT

interactionId = 100
issuerId = GVT.name
proverId = '12'
verifierId = '13'


def testInteraction():
    attrRepo = InMemoryAttrRepo()
    attrs = GVT.attribs(name='Aditya Pratap Singh', age=25, sex='male')
    attrNames = tuple(attrs.keys())
    revealedAttrs = ["age", ]
    encodedAttrs = attrs.encoded()

    credName = "Profile"
    credVersion = "1.0"
    attrRepo.addAttributes(proverId, attrs)

    issuer = Issuer(issuerId, attrRepo)
    issuer.newCredDef(attrNames, credName, credVersion,
                      p_prime=P_PRIME1, q_prime=Q_PRIME1)
    prover = Prover(proverId)
    verifier = Verifier(verifierId)

    proofBuilder = prover.createProofBuilder(issuer, attrNames, interactionId, verifier,
                                             encodedAttrs, revealedAttrs)

    proof = proofBuilder.prepareProof(proofBuilder.credDefPks, proofBuilder.masterSecret,
                                      proofBuilder.credential,
                                      proofBuilder.attrs,
                                      proofBuilder.revealedAttrs, proofBuilder.nonce)

    assert verifier.verify(issuer, credName, credVersion, proof,
                           proofBuilder.nonce, proofBuilder.attrs,
                           proofBuilder.revealedAttrs)
