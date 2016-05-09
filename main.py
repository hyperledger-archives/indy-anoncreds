from protocol.issuer import Issuer
from protocol.prover import Prover
from protocol.verifier import Verifier
from protocol.utils import encodeAttrs

# Create a dictionary of attributes to share
# {'1': name, '2': age, '3': sex}
attrs = {'1': 'Aditya Pratap Singh', '2': '25', '3': 'male'}
# Encode the attributes such that none of them exceed 256 integer limit imposed by AnonCreds
attrs = encodeAttrs(attrs)

# Create issuer and get its public key
issuer = Issuer(len(attrs))
pk_i, sk_i = issuer.gen_key_pair()

prover = Prover(pk_i)
prover.set_attrs(attrs)

A, e, vprimeprime = issuer.issuance(prover.U, attrs)
v = prover.vprime + vprimeprime
credential = (attrs, A, e, v)

# Setup verifier
verifier = Verifier(pk_i)
nonce = verifier.get_nonce()

revealed_attrs = ['1']
proof = prover.prepare_proof(attrs, revealed_attrs, A, e, v, nonce)

assert verifier.verify_proof(proof, nonce)






