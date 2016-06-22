from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.prover import Prover
from anoncreds.protocol.verifier import Verifier
from anoncreds.protocol.utils import encodeAttrs

# Create a dictionary of attributes to share
# {'1': name, '2': age, '3': sex, '4': 'status'}
attrs_gvt = {'name': 'Aditya Pratap Singh', 'age': '25', 'sex': 'male'}
attrs_ibm = {'status': 'ACTIVE'}
attrs = dict(list(attrs_gvt.items()) + list(attrs_ibm.items()))


# Encode the attributes such that none of them exceed 256 bit integer limit
# imposed by AnonCreds
encodedAttrs = encodeAttrs(attrs)
encodedAttrsDict = {"gvt": encodeAttrs(attrs_gvt),
                    "ibm": encodeAttrs(attrs_ibm)}

# Create multiple issuers and get there public key
issuer_gvt = Issuer(list(attrs_gvt.keys()))
pk_i_gvt = issuer_gvt.PK

issuer_ibm = Issuer(list(attrs_ibm.keys()))
pk_i_ibm = issuer_ibm.PK

issuers = {"gvt": issuer_gvt, "ibm": issuer_ibm}

pk_i = {"gvt": pk_i_gvt, "ibm": pk_i_ibm}
prover = Prover(pk_i=pk_i)
prover.set_attrs(encodedAttrs)

presentationToken = {}
for key, val in prover.U.items():
    issuer = issuers[key]
    A, e, vprimeprime = issuer.issue(val, encodedAttrsDict[key])
    v = prover.vprime[key] + vprimeprime
    presentationToken[key] = {"A": A, "e": e, "v": v}

# Setup verifier
verifier = Verifier(pk_i=pk_i)
nonce = verifier.Nonce

# Prepare proof
revealedAttrs = ['name']
proof = prover.prepare_proof(credential=presentationToken, attrs=encodedAttrs,
                             revealedAttrs=revealedAttrs, nonce=nonce,
                             encodedAttrsDict=encodedAttrsDict)

# Verify the proof
verify_status = verifier.verify_proof(proof=proof, nonce=nonce,
                                      attrs=encodedAttrs,
                                      revealedAttrs=revealedAttrs,
                                      encodedAttrsDict=encodedAttrsDict)

if verify_status:
    print("Proof verified")
else:
    print("Proof not valid")
