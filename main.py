from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.prover import Prover
from anoncreds.protocol.verifier import Verifier
from anoncreds.protocol.utils import encodeAttrs
from anoncreds.protocol.models import Credential
from charm.core.math.integer import integer

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
issuer_gvt = Issuer(list(attrs_gvt.keys()), True,
                    p_prime=integer(157329491389375793912190594961134932804032426403110797476730107804356484516061051345332763141806005838436304922612495876180233509449197495032194146432047460167589034147716097417880503952139805241591622353828629383332869425029086898452227895418829799945650973848983901459733426212735979668835984691928193677469),
                    q_prime=integer(151323892648373196579515752826519683836764873607632072057591837216698622729557534035138587276594156320800768525825023728398410073692081011811496168877166664537052088207068061172594879398773872352920912390983199416927388688319207946493810449203702100559271439586753256728900713990097168484829574000438573295723))
pk_i_gvt = issuer_gvt.PK

issuer_ibm = Issuer(list(attrs_ibm.keys()), True,
                    p_prime=integer(161610459843908464667375821118575168226824282956978821640797520118616859558961395880196315322096458106037206290868757601849707785880099537257189258219310327562762606210985076067812502086850423537117076322748909902963854862506532321771281911610699500914980160157551242572791240516218628370968129992429972981803),
                    q_prime=integer(161493723223168517065151437243922053019267475361571371307287673539394775034094894440069890843406501007646183281736425436358728443271869768433133470245946207962338444877914886535613027325276708068934388710720146654092114476897070184618062196075578729368908143775530777165436283189882519306831269291698587939219))
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
    presentationToken[key] = Credential(A, e, v)

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
