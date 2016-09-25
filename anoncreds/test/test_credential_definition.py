from anoncreds.protocol.cred_def_secret_key import CredDefSecretKey


def testSerialization(gvtSecretKey: CredDefSecretKey):
    serializedSk = str(gvtSecretKey)
    deserializedSk = CredDefSecretKey.fromStr(serializedSk)
    assert gvtSecretKey == deserializedSk
    p_prime = deserializedSk.p_prime
    q_prime = deserializedSk.q_prime
    assert gvtSecretKey.p_prime == p_prime
    assert gvtSecretKey.q_prime == q_prime
