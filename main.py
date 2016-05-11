from protocol.issuer import Issuer
from protocol.prover import Prover
from protocol.verifier import Verifier
from protocol.utils import encodeAttrs

# Create a dictionary of attributes to share
# {'1': name, '2': age, '3': sex}
attrs = {'1': 'Aditya Pratap Singh', '2': '25', '3': 'male'}
# Encode the attributes such that none of them exceed 256 integer limit
# imposed by AnonCreds
attrs = encodeAttrs(attrs)

# Create issuer and get its public key
issuer = Issuer(len(attrs))
pk_i, sk_i = issuer.key_pair

prover = Prover(pk_i)
prover.set_attrs(attrs)

A, e, vprimeprime = issuer.issuance(prover.U, attrs)
v = prover.vprime + vprimeprime
credential = {"attrs": attrs, "A": A, "e": e, "v": v}

# Setup verifier
verifier = Verifier(pk_i)
nonce = verifier.get_nonce()

# Prepare proof
revealed_attrs = ['1']
proof = prover.prepare_proof(credential, revealed_attrs, nonce)

# Verify the proof
verify_status = verifier.verify_proof(proof, nonce, attrs)

if verify_status:
    print("Proof verified")
else:
    print("Proof not valid")
