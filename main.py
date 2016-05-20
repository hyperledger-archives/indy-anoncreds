from protocol.issuer import Issuer
from protocol.prover import Prover
from protocol.verifier import Verifier
from protocol.utils import encodeAttrs, get_tuple_dict

# Create a dictionary of attributes to share
# {'1': name, '2': age, '3': sex, '4': 'status'}
attrs_gvt = {'1': 'Aditya Pratap Singh', '2': '25', '3': 'male'}
attrs_ibm = {'4': 'ACTIVE'}
attrs = dict(list(attrs_gvt.items()) + list(attrs_ibm.items()))


# Encode the attributes such that none of them exceed 256 bit integer limit
# imposed by AnonCreds
encodedAttrs = encodeAttrs(attrs)
encodedAttrsDict = {"gvt": encodeAttrs(attrs_gvt), "ibm": encodeAttrs(attrs_ibm)}

# Create multiple issuers and get there public key
issuer_gvt = Issuer(len(attrs_gvt))
pk_i_gvt = issuer_gvt.PK

issuer_ibm = Issuer(len(attrs_ibm))
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
revealedAttrs = ['1']
proof = prover.prepare_proof(credential=presentationToken, attrs=encodedAttrs,
                             revealed_attrs=revealedAttrs, nonce=nonce,
                             encodedAttrsDict=encodedAttrsDict)

# Verify the proof
verify_status = verifier.verify_proof(proof=proof, nonce=nonce,
                                      attrs=encodedAttrs, revealed_attrs=revealedAttrs,
                                      encodedAttrsDict=encodedAttrsDict)

if verify_status:
    print("Proof verified")
else:
    print("Proof not valid")
