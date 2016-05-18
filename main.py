from protocol.issuer import Issuer
from protocol.prover import Prover
from protocol.verifier import Verifier
from protocol.utils import encodeAttrs

# Create a dictionary of attributes to share
# {'1': name, '2': age, '3': sex}
attrs = {'1': 'Aditya Pratap Singh', '2': '25', '3': 'male'}
# Encode the attributes such that none of them exceed 256 bit integer limit
# imposed by AnonCreds
encodedAttrs = encodeAttrs(attrs)

# Create multiple issuers and get there public key
issuer_gvt = Issuer(len(encodedAttrs))
pk_i_gvt = issuer_gvt.PK

issuer_ibm = Issuer(len(encodedAttrs))
pk_i_ibm = issuer_ibm.PK

issuers = {"gvt": issuer_gvt, "ibm": issuer_ibm}

# TODO:AS: This dictionary needs to be fetched from some store
pk_i = {"gvt": pk_i_gvt, "ibm": pk_i_ibm}
prover = Prover(pk_i=pk_i)
prover.set_attrs(encodedAttrs)

presentationToken = {}
for key, val in prover.U.items():
    issuer = issuers[key]
    A, e, vprimeprime = issuer.issue(val, encodedAttrs)
    v = prover.vprime + vprimeprime
    presentationToken[key] = {"A": A, "e": e, "v": v}

# Setup verifier
verifier = Verifier(pk_i=pk_i)
nonce = verifier.Nonce

# Prepare proof
revealedAttrs = ['1']
proof = prover.prepare_proof(credential=presentationToken, attrs=encodedAttrs,
                             revealed_attrs=revealedAttrs, nonce=nonce)

# Verify the proof
verify_status = verifier.verify_proof(proof=proof, nonce=nonce,
                                      attrs=encodedAttrs, revealed_attrs=revealedAttrs)

if verify_status:
    print("Proof verified")
else:
    print("Proof not valid")
