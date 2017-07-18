import socket
import json
import asyncio
import logging

from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.repo.attributes_repo import AttributeRepoInMemory
from anoncreds.protocol.repo.public_repo import PublicRepoInMemory
from anoncreds.protocol.types import PredicateGE, \
    ID, AttributeInfo, ProofRequest, FullProof, PublicKey
from anoncreds.protocol.verifier import Verifier
from anoncreds.protocol.wallet.issuer_wallet import IssuerWalletInMemory
from anoncreds.protocol.wallet.wallet import WalletInMemory
from anoncreds.test.conftest import GVT

logging.basicConfig(format=u'%(filename)s[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s',
                    level=logging.DEBUG)

loop = asyncio.get_event_loop()
global_dict = {
    'verifier': '',
    'proof_request': '',
    'public_key': ''
}
ip = '127.0.0.1'
port = 1234
chunk_size = 102400


def main():
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((ip, port))
    sock.listen(1)
    logging.debug('Listening')
    conn, _ = sock.accept()
    logging.debug('Connected')

    while True:
        data = json.loads(conn.recv(chunk_size).decode("utf-8"))
        logging.debug('received data: {}'.format(data))
        if ('type' in data) & (data['type'] == 'receive_claim_def'):
            logging.debug('receive_claim_def -> start')
            global global_dict
            global_dict['public_key'] = PublicKey.from_str_dict(data['data']['data']['primary'])
            logging.debug('receive_claim_def -> done')
        if ('type' in data) & (data['type'] == 'get_proof_request'):
            logging.debug('get_proof_request -> start')
            create_request = asyncio.ensure_future(create_proof_request(conn))
            loop.run_until_complete(create_request)
            logging.debug('get_proof_request -> done')
        if ('type' in data) & (data['type'] == 'check_proof'):
            logging.debug('check_proof -> start')
            check_proof = asyncio.ensure_future(verify(data['data'], conn))
            loop.run_until_complete(check_proof)
            logging.debug('check_proof -> done')
        if (('type' in data) & (data['type'] == 'close')) | (not data):
            break

    sock.close()


async def create_proof_request(conn):
    # 1. Init entities
    public_repo = PublicRepoInMemory()
    attr_repo = AttributeRepoInMemory()
    issuer = Issuer(IssuerWalletInMemory('issuer1', public_repo), attr_repo)

    # 2. Create a Schema
    schema = await issuer.genSchema('GVT', '1.0', GVT.attribNames())
    schema_id = ID(schema.getKey())

    # 3. Create keys for the Schema
    global global_dict
    await issuer.wallet.submitPublicKeys(schema_id, global_dict['public_key'])

    # 4. set attributes for user1
    prover_id = 'BzfFCYk'
    attributes = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    attr_repo.addAttributes(schema.getKey(), prover_id, attributes)

    verifier = Verifier(WalletInMemory('verifier1', public_repo))

    proof_request = ProofRequest(
        name='Test_proof', version='1.0',
        nonce=verifier.generateNonce(),
        verifiableAttributes={'attr_uuid': AttributeInfo('name', schema.seqId)},
        predicates={'predicate_uuid': PredicateGE('age', 18)})

    global_dict['verifier'] = verifier
    global_dict['proof_request'] = proof_request

    conn.send(json.dumps(proof_request.to_str_dict()).encode())

async def verify(proof, conn):
    proof = FullProof.from_str_dict(proof, [global_dict['public_key'].N])

    assert proof.requestedProof.revealed_attrs['attr_uuid'][1] == 'Alex'
    valid = await global_dict['verifier'].verify(global_dict['proof_request'], proof)

    conn.send(json.dumps(valid).encode())

if __name__ == '__main__':
    main()
