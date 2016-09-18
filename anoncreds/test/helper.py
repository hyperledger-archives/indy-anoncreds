from anoncreds.protocol.types import CredDefId

def verifyEquality(attrRepo, revealedAttrs, issuers, prover, verifiers, primes, defaultNonce=None, defaultU=None):
    # create credentials definition
    credDefIds, encodedAttrs = _getCredentialDefinitions(issuers, attrRepo, prover, primes)

    # init proof builder
    proofBuilder = prover.createProofBuilder(credDefIds)

    # issue credentials
    creds = _issueCredentials(issuers, credDefIds, prover, proofBuilder, defaultU)

    # verify
    verified = True
    for verifier in verifiers:
        proofVerifier = verifier.createProofVerifier(credDefIds)
        nonce = defaultNonce if defaultNonce else proofVerifier.nonce
        proof = proofBuilder.prepareProofEquality(creds,
                                                  encodedAttrs, revealedAttrs,
                                                  nonce)
        verifStatus = proofVerifier.verifyEquality(proof, encodedAttrs, revealedAttrs)
        if not verifStatus:
            verified = False

    return verified


def verifyPredicateGreaterEq(attrRepo, revealedAttrs, issuers, prover, verifiers, primes, predicate, defaultNonce=None, defaultU=None):
    # create credentials definition
    credDefIds, encodedAttrs = _getCredentialDefinitions(issuers, attrRepo, prover, primes)

    # init proof builder
    proofBuilder = prover.createProofBuilder(credDefIds)

    # issue credentials
    creds = _issueCredentials(issuers, credDefIds, prover, proofBuilder, defaultU)

    # verify
    verified = True
    for verifier in verifiers:
        proofVerifier = verifier.createProofVerifier(credDefIds)
        nonce = defaultNonce if defaultNonce else proofVerifier.nonce
        proof = proofBuilder.prepareProofPredicateGreaterEq(creds,
                                                  encodedAttrs, revealedAttrs,
                                                  nonce, predicate)
        verifStatus = proofVerifier.verifyPredicateGreaterEq(proof,
                                                             encodedAttrs, revealedAttrs,
                                                             predicate)
        if not verifStatus:
            verified = False

    return verified


def _getCredentialDefinitions(issuers, attrRepo, prover, primes):
    credDefIds = {}
    encodedAttrs = {}
    for issuer in issuers:
        attrs = attrRepo.getAttributes(prover.id, issuer.id)
        attrNames = attrs.keys()
        encodedAttrs = {**encodedAttrs, **attrs.encoded()}

        credDefId = CredDefId("Profile", "1.0", attrNames)
        credDefIds[issuer.id] = credDefId
        issuer.addNewCredDef(credDefId.attrNames, credDefId.name, credDefId.version, **primes)

    return (credDefIds, encodedAttrs)

def _issueCredentials(issuers, credDefIds, prover, proofBuilder, defaultU=None):
    creds = {}
    for issuer in issuers:
        id = issuer.id
        U = defaultU if defaultU else proofBuilder.U[id]
        cred = issuer.createCred(prover.id, credDefIds[id], U)
        creds[id] = cred

    return creds
