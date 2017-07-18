import socket
import json
import asyncio
import logging

from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.repo.attributes_repo import AttributeRepoInMemory
from anoncreds.protocol.repo.public_repo import PublicRepoInMemory
from anoncreds.protocol.types import ID, ClaimRequest
from anoncreds.protocol.wallet.issuer_wallet import IssuerWalletInMemory
from anoncreds.test.conftest import GVT, primes1

logging.basicConfig(format=u'%(filename)s[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s',
                    level=logging.DEBUG)

loop = asyncio.get_event_loop()
global_dict = {}
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
        if ('type' in data) & (data['type'] == 'get_claim_def'):
            logging.debug('get_claim_def -> start')
            init = asyncio.ensure_future(issuer_init(primes1(), conn))
            loop.run_until_complete(init)
            logging.debug('get_claim_def -> done')
        if ('type' in data) & (data['type'] == 'issue_claim'):
            logging.debug('issue_claim -> start')
            future = asyncio.ensure_future(issue_claim(conn, data['data']['blinded_ms']))
            loop.run_until_complete(future)
            logging.debug('issue_claim -> done')
        if (('type' in data) & (data['type'] == 'close')) | (not data):
            break

    sock.close()

async def issuer_init(primes, conn):
    # 1. Init entities
    public_repo = PublicRepoInMemory()
    attr_repo = AttributeRepoInMemory()
    issuer = Issuer(IssuerWalletInMemory('issuer1', public_repo), attr_repo)

    # 2. Create a Schema
    schema = await issuer.genSchema('GVT', '1.0', GVT.attribNames())
    schema_id = ID(schema.getKey())

    # 3. Create keys for the Schema
    await issuer.genKeys(schema_id, **primes)

    # 4. Issue accumulator
    await issuer.issueAccumulator(schemaId=schema_id, iA='110', L=5)

    # 4. set attributes for user1
    prover_id = 'BzfFCYk'
    attributes = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    attr_repo.addAttributes(schema.getKey(), prover_id, attributes)

    public_key = await issuer.wallet.getPublicKey(schema_id)

    global global_dict
    global_dict = {
        'schema_id': schema_id,
        'public_key': public_key,
        'issuer': issuer
    }

    conn.send(json.dumps({
        'primary': public_key.to_str_dict(),
        'revocation': None
    }).encode())


async def issue_claim(conn, claim_request):
    claim_request = ClaimRequest.from_str_dict(claim_request, global_dict['public_key'].N)

    (signature, claims) = await global_dict['issuer'].issueClaim(global_dict['schema_id'], claim_request)

    msg = {
        'signature': signature.to_str_dict(),
        'claim': {el: claims[el].to_str_dict() for el in claims}
    }

    conn.send(json.dumps(msg).encode())

if __name__ == '__main__':
    main()
