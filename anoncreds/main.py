from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.utils import encodeAttrs
from anoncreds.protocol.verifier import Verifier
from anoncreds.protocol.prover import Prover

# Create a dictionary of attributes to share
# {'1': name, '2': age, '3': sex}
attrs = {'1': 'Aditya Pratap Singh', '2': '25', '3': 'male'}
# Encode the attributes such that none of them exceed 256 bit integer limit
# imposed by AnonCreds
encodedAttrs = encodeAttrs(attrs)

# Create issuer and get its public key
issuer = Issuer(len(encodedAttrs))
pk_i = issuer.PK

prover = Prover(pk_i)
prover.set_attrs(encodedAttrs)

A, e, vprimeprime = issuer.issue(prover.U, encodedAttrs)
v = prover.vprime + vprimeprime
presentationToken = {"encodedAttrs": encodedAttrs, "A": A, "e": e, "v": v}

# Setup verifier
verifier = Verifier(pk_i)
nonce = verifier.Nonce

# Prepare proof
revealedAttrs = ['1']
proof = prover.prepare_proof(presentationToken, revealedAttrs, nonce)

# Verify the proof
verify_status = verifier.verify_proof(proof, nonce, encodedAttrs)

if verify_status:
    print("Proof verified")
else:
    print("Proof not valid")
