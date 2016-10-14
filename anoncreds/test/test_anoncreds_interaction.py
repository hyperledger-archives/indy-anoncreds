from anoncreds.protocol.attribute_repo import InMemoryAttrRepo
from anoncreds.protocol.credential_definition import CredentialDefinition
from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.issuer_key import IssuerKey
from anoncreds.protocol.issuer_secret_key import IssuerSecretKey
from anoncreds.protocol.prover import Prover
from anoncreds.protocol.verifier import Verifier
from anoncreds.test.conftest import GVT
from anoncreds.test.cred_def_test_store import MemoryCredDefStore
from anoncreds.test.issuer_key_test_store import MemoryIssuerKeyStore
from anoncreds.test.issuer_secret_key_test_store import \
    MemoryIssuerSecretKeyStore

interactionId = 100
issuerId = GVT.name
proverId = '12'
verifierId = '13'


def testInteraction(gvtSecretKey):
    mcds = MemoryCredDefStore()

    miks = MemoryIssuerKeyStore()

    attrRepo = InMemoryAttrRepo()

    attrs = GVT.attribs(name='John Anthony White',
                        age=41,
                        sex='male')
    attrNames = tuple(attrs.keys())
    revealedAttrs = ["age", ]
    encodedAttrs = attrs.encoded()

    credName = "Profile"
    credVersion = "1.0"
    attrRepo.addAttributes(proverId, attrs)

    misks = MemoryIssuerSecretKeyStore()
    issuer = Issuer(issuerId, attrRepo, credDefStore=mcds,
                    issuerSecretKeyStore=misks)
    credDefId = 1

    cd = CredentialDefinition(credDefId, attrNames, credName, credVersion)
    mcds.publishCredDef(cd)

    # Issuer Key set up
    issuerKeyId = 1
    issuerSecretKey = IssuerSecretKey(cd, sk=gvtSecretKey, uid=issuerKeyId)
    misks.put(issuerSecretKey)
    issuerKey = issuerSecretKey.PK

    miks.publishIssuerKey(issuerKey)

    # issuer.addNewCredDef(cd)
    prover = Prover(proverId, mcds, miks)
    verifier = Verifier(verifierId, mcds, miks)
    nonce = verifier.generateNonce(interactionId)
    proofBuilder = prover.newProofBuilder(issuerKeyId, issuerId)
    credential = issuer.createCred(proverId,
                                   cduid=credDefId,
                                   name=credName,
                                   version=credVersion,
                                   U=proofBuilder.U[issuerId])

    presentationToken = proofBuilder.getPresentationToken(issuer.id, credential)
    proofBuilder.setParams(presentationToken, revealedAttrs, nonce)

    proof = proofBuilder.prepareProof(proofBuilder.issuerPks,
                                      proofBuilder.masterSecret,
                                      proofBuilder.credential,
                                      encodedAttrs,
                                      proofBuilder.revealedAttrs,
                                      proofBuilder.nonce)
    assert verifier.verify(issuerId=issuer.id,
                           name=credName,
                           version=credVersion,
                           proof=proof,
                           nonce=proofBuilder.nonce,
                           attrs=encodedAttrs,
                           revealedAttrs=proofBuilder.revealedAttrs,
                           credDefId=credDefId,
                           issuerKeyId=issuerKeyId)
