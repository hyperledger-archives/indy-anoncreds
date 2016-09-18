from anoncreds.protocol.credential_definition import getDeserializedSK, getPPrime, getQPrime


def testSerialization(gvtCredDef):
    sk = gvtCredDef.SK
    serializedSk = gvtCredDef.serializedSK
    deserializedSk = getDeserializedSK(serializedSk)
    assert sk == deserializedSk
    p_prime = getPPrime(deserializedSk)
    q_prime = getQPrime(deserializedSk)
    assert gvtCredDef.p_prime == p_prime
    assert gvtCredDef.q_prime == q_prime


def testCredDefinitionInternalMatches(gvtCredDef):
    assert gvtCredDef.credentialDefinition.name == gvtCredDef.name
    assert gvtCredDef.credentialDefinition.version == gvtCredDef.version
    assert gvtCredDef.credentialDefinition.ip == gvtCredDef.ip
    assert gvtCredDef.credentialDefinition.port == gvtCredDef.port
    assert gvtCredDef.credentialDefinition.pk == gvtCredDef.PK
