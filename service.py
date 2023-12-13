from hashlib import sha256
import json
import time
import datetime

from flask import Flask, request,render_template,redirect,flash
import requests


CONNECTED_SERVICE_ADDRESS = "http://127.0.0.1:5000"
POLITICAL_PARTIES = ["Party A", "Republican Party", "Socialist party"]
VOTER_IDS = ['VOID001', 'VOID002', 'VOID003', 'VOID004', 'VOID005', 'VOID006', 'VOID007', 'VOID008', 'VOID009',
             'VOID010', 'VOID011', 'VOID012', 'VOID013', 'VOID014', 'VOID015']

vote_check = set()

posts = []


class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        """
        Initializes a new block with the given parameters.
        """
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce

    def compute_hash(self):
        """
        Computes and returns the hash of the block contents.
        """
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()


class Blockchain:
    # Difficulty of our Proof of Work algorithm
    difficulty = 2

    def __init__(self):
        """
        Initializes a new blockchain with empty lists for unconfirmed transactions and the chain.
        """
        self.unconfirmed_transactions = []
        self.chain = []

    def create_genesis_block(self):
        """
        Generates a genesis block and appends it to the chain.
        """
        genesis_block = Block(0, [], 0, "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    @property
    def last_block(self):
        """
        Returns the last block in the chain.
        """
        return self.chain[-1]

    def add_block(self, block, proof):
        """
        Adds a block to the chain after verification.
        """
        previous_hash = self.last_block.hash

        if previous_hash != block.previous_hash:
            return False

        if not Blockchain.is_valid_proof(block, proof):
            return False

        block.hash = proof
        self.chain.append(block)
        return True

    @staticmethod
    def proof_of_work(block):
        """
        Tries different values of nonce to get a hash that satisfies the difficulty criteria.
        """
        block.nonce = 0

        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()

        return computed_hash

    def add_new_transaction(self, transaction):
        """
        Adds a new transaction to the list of unconfirmed transactions.
        """
        self.unconfirmed_transactions.append(transaction)

    @classmethod
    def is_valid_proof(cls, block, block_hash):
        """
        Checks if block_hash is a valid hash of the block and satisfies the difficulty criteria.
        """
        return (block_hash.startswith('0' * Blockchain.difficulty) and
                block_hash == block.compute_hash())

    @classmethod
    def check_chain_validity(cls, chain):
        """
        Checks the validity of a given chain.
        """
        result = True
        previous_hash = "0"

        for block in chain:
            block_hash = block.hash
            delattr(block, "hash")

            if not cls.is_valid_proof(block, block_hash) or \
                    previous_hash != block.previous_hash:
                result = False
                break

            block.hash, previous_hash = block_hash, block_hash

        return result

    def mine(self):
        """
        Adds pending transactions to the blockchain by creating a new block and performing Proof of Work.
        """
        if not self.unconfirmed_transactions:
            return False

        last_block = self.last_block

        new_block = Block(index=last_block.index + 1,
                          transactions=self.unconfirmed_transactions,
                          timestamp=time.time(),
                          previous_hash=last_block.hash)

        proof = self.proof_of_work(new_block)
        self.add_block(new_block, proof)

        self.unconfirmed_transactions = []

        return True


app = Flask(__name__)

# The node's copy of the blockchain
blockchain = Blockchain()
blockchain.create_genesis_block()

# The addresses of other participating members of the network
peers = set()


@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    """
    Handles incoming new transaction requests.
    """
    tx_data = request.get_json()
    required_fields = ["voter_id", "party"]

    for field in required_fields:
        if not tx_data.get(field):
            return "Invalid transaction data", 404

    tx_data["timestamp"] = time.time()

    blockchain.add_new_transaction(tx_data)

    return "Success", 201


@app.route('/chain', methods=['GET'])
def get_chain():
    """
    Handles incoming requests to get the node's copy of the blockchain.
    """
    chain_data = [block.__dict__ for block in blockchain.chain]
    return json.dumps({"length": len(chain_data),
                       "chain": chain_data,
                       "peers": list(peers)})


@app.route('/mine', methods=['GET'])
def mine_unconfirmed_transactions():
    """
    Handles incoming requests to mine unconfirmed transactions.
    """
    result = blockchain.mine()
    if not result:
        return "No transactions to mine"
    else:
        chain_length = len(blockchain.chain)
        consensus()
        if chain_length == len(blockchain.chain):
            announce_new_block(blockchain.last_block)
        return "Block #{} is mined.".format(blockchain.last_block.index)


# Endpoint to add new peers to the network.
@app.route('/register_node', methods=['POST'])
def register_new_peers():
    """
    Handles incoming requests to register new peers.
    """
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    peers.add(node_address)

    return get_chain()


@app.route('/register_with', methods=['POST'])
def register_with_existing_node():
    """
    Internally calls the `register_node` endpoint to register the current node with the specified node.
    """
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    data = {"node_address": request.host_url}
    headers = {'Content-Type': "application/json"}

    response = requests.post(node_address + "/register_node",
                             data=json.dumps(data), headers=headers)

    if response.status_code == 200:
        global blockchain
        global peers
        chain_dump = response.json()['chain']
        blockchain = create_chain_from_dump(chain_dump)
        peers.update(response.json()['peers'])
        return "Registration successful", 200
    else:
        return response.content, response.status_code


def create_chain_from_dump(chain_dump):
    """
    Creates a new blockchain from a chain dump.
    """
    generated_blockchain = Blockchain()
    generated_blockchain.create_genesis_block()
    for idx, block_data in enumerate(chain_dump):
        if idx == 0:
            continue
        block = Block(block_data["index"],
                      block_data["transactions"],
                      block_data["timestamp"],
                      block_data["previous_hash"],
                      block_data["nonce"])
        proof = block_data['hash']
        added = generated_blockchain.add_block(block, proof)
        if not added:
            raise Exception("The chain dump is tampered!!")
    return generated_blockchain


@app.route('/add_block', methods=['POST'])
def verify_and_add_block():
    """
    Handles incoming requests to verify and add a block mined by someone else.
    """
    block_data = request.get_json()
    block = Block(block_data["index"],
                  block_data["transactions"],
                  block_data["timestamp"],
                  block_data["previous_hash"],
                  block_data["nonce"])

    proof = block_data['hash']
    added = blockchain.add_block(block, proof)

    if not added:
        return "The block was discarded by the node", 400

    return "Block added to the chain", 201


# Endpoint to query unconfirmed transactions
@app.route('/pending_tx')
def get_pending_tx():
    """
    Handles incoming requests to get unconfirmed transactions.
    """
    return json.dumps(blockchain.unconfirmed_transactions)


def fetch_posts():
    """
    Function to fetch the chain from a blockchain node, parse the
    data and store it locally.
    """
    get_chain_address = "{}/chain".format(CONNECTED_SERVICE_ADDRESS)
    response = requests.get(get_chain_address)
    if response.status_code == 200:
        content = []
        vote_count = []
        chain = json.loads(response.content)
        for block in chain["chain"]:
            for tx in block["transactions"]:
                tx["index"] = block["index"]
                tx["hash"] = block["previous_hash"]
                content.append(tx)

        global posts
        posts = sorted(content, key=lambda k: k['timestamp'], reverse=True)

def timestamp_to_string(epoch_time):
    """
    Convert epoch timestamp to a human-readable string format.
    """
    return datetime.datetime.fromtimestamp(epoch_time).strftime('%Y-%m-%d %H:%M')

@app.route('/')
def index():
    fetch_posts()

    vote_gain = [post["party"] for post in posts]

    return render_template('index.html',
                           title='Server Backend',
                           posts=posts,
                           vote_gain=vote_gain,
                           node_address=CONNECTED_SERVICE_ADDRESS,
                           readable_time=timestamp_to_string,
                           political_parties=POLITICAL_PARTIES,
                           voter_ids=VOTER_IDS)


@app.route('/submit', methods=['POST'])
def submit_textarea():
    party = request.form["party"]
    voter_id = request.form["voter_id"]

    if voter_id not in VOTER_IDS:
        flash('Voter ID invalid, please select voter ID from sample!', 'error')
    elif voter_id in vote_check:
        flash(f'Voter ID ({voter_id}) already voted!', 'error')
    else:
        vote_check.add(voter_id)
        post_object = {'voter_id': voter_id, 'party': party}
        new_tx_address = f"{CONNECTED_SERVICE_ADDRESS}/new_transaction"
        requests.post(new_tx_address, json=post_object, headers={'Content-type': 'application/json'})
        flash(f'Voted to {party} successfully!', 'success')

    return redirect('/')

def consensus():
    """
    Naive consensus algorithm. Replaces the local chain with a longer valid chain if found.
    """
    global blockchain

    longest_chain = None
    current_len = len(blockchain.chain)

    for node in peers:
        response = requests.get('{}chain'.format(node))
        length = response.json()['length']
        chain = response.json()['chain']
        if length > current_len and blockchain.check_chain_validity(chain):
            current_len = length
            longest_chain = chain

    if longest_chain:
        blockchain = longest_chain
        return True

    return False


def announce_new_block(block):
    """
    Announces a newly mined block to the network.
    """
    for peer in peers:
        url = "{}add_block".format(peer)
        headers = {'Content-Type': "application/json"}
        requests.post(url,
                      data=json.dumps(block.__dict__, sort_keys=True),
                      headers=headers)


if __name__ == '__main__':
    app.secret_key = '6dbf23122cb5046cc5c0c1b245c75f8e43c59ca8ffeac292715e5078e631d0c9'
    app.config['SESSION_TYPE'] = 'filesystem'
    app.run(debug=True, port=5000)