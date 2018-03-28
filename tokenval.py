# Simple token processing/validation logic
# It is implicitly assumed that all Bitcoin transactions are valid. Validation of Bitcoin transactions is not part of sito
import logging
import bitcoin
from tokenio import TokenTransaction, OnchainTransaction
log = logging.getLogger(__name__)

# key value store with same interface as dict / shelve
db=None

def set_db(db_):
    global db
    db = db_

def privKey(addr):
    if "PRIVKEY_"+addr in db:
        return db["PRIVKEY_"+addr]
    else:
        return None

class RegisteredToken:
    """ A token registered in the DB, identified by address. """
    def __init__(self, addr, tokenid):
        self.addr = addr
        self.tokenid = tokenid
        self.handle="TOKEN_"+self.addr
    def __str__(self):
        return self.tokenid+":"+self.addr

def tok2addr(tok):
    for key in db:
        if key.startswith("TOKEN_"):
            rt = db[key]
            if rt.tokenid == tok:
                return rt.addr
    return None

class UnspentOutput:
    """ Unspent output on token chain. Unspent outputs that are blank tokens still to be minted have a value of None. """
    def __init__(self, tokaddr, txhash, outnum, bch_value, value):
        self.token_addr = tokaddr
        self.txhash = txhash
        self.outnum = outnum
        self.bch_value = bch_value
        self.value = value
    def __str__(self):
        h = self.token_addr
        thandle = "TOKEN_"+self.token_addr
        if thandle in db:
            h = db[thandle].tokenid

        return h+":"+self.txhash+":"+str(self.outnum)+":"+str(self.value)+":"+str(self.bch_value)

def allUnspentOutputs():
    outs = []
    for key in db:
        if key.startswith("UNSPENT_"):
            outs.append(db[key])
    return outs

def unspentOutputsForToken(addr):
    outs = []
    for key in db:
        if key.startswith("UNSPENT_"):
            utxo = db[key]
            if utxo.token_addr == addr:
                outs.append(utxo)
    return outs

def unspentBlank(addr):
    """ Return first blank output found for address addr. """
    outs = allUnspentOutputs()
    for out in outs:
        if out.token_addr == addr and out.value is None:
            return out
    return None

def getBalances():
    """ Available (spendable) balances for all tokens. FIXME: super inefficient..."""
    addr2tokenid = {}
    for key in db:
        if key.startswith("TOKEN_"):
            rt = db[key]
            addr2tokenid[rt.addr] = rt.tokenid

    balances = {}
    outputs = allUnspentOutputs()
    for out in outputs:
        if out.token_addr not in addr2tokenid:
            continue

        tokenid = addr2tokenid[out.token_addr]

        if "BCH_"+out.txhash not in db:
            continue

        tx = db["BCH_"+out.txhash]
        spend_addr = bitcoin.script_to_address(tx.decoded["outs"][out.outnum]["script"])
        if privKey(spend_addr) is None:
            if tokenid not in balances:
                balances[tokenid] = 0
            continue

        value = 0 if out.value is None else out.value

        if tokenid in balances:
            balances[tokenid] += value
        else:
            balances[tokenid] = value
    return balances

def processToken(txn):
    """ Just store token transactions in DB. Real validation happens in processOnchain below. """
    if txn.handle in db:
        log.warning("Have seen toktxn %s already.", txn.handle)
        return
    if "TOKEN_"+txn.token_addr not in db:
        log.error("Toktxn %s is dealing with unknown token.", txn.handle)
        return
    db[txn.handle] = txn


def processOnchain(txn):
    if txn.handle in db:
        log.warning("Have seen and processed on chain transaction %s already.", txn.handle)
        return

    # find and extract OP_RETURN data if available
    opreturn_data = None
    for output in txn.decoded["outs"]:
        assert("script" in output)
        if output["script"].startswith("6a"): # OP_RETURN?
            opreturn_data = output["script"][4:] # skip length byte

    if opreturn_data is None:
        # transactions without OP_RETURN data are of interest for
        # their BCH outputs (to fill up miner fees)
        # and the potential tokens that can be created from these outputs.

        log.info("Assuming transaction %s is generating transaction or meant for extra BCH fee input", txn.handle)
        for n, output in enumerate(txn.decoded["outs"]):
            script = output["script"]
            out_addr = bitcoin.script_to_address(script)
            log.info("Generating unspent blank output %s:%s:%d:%d",
                     out_addr, txn.hsh, n, output["value"])
            key = "UNSPENT_"+txn.hsh+("_%d" % n)
            if key in db:
                log.error("Internal error, outpoint already in DB.")
                return
            db[key]=UnspentOutput(out_addr, txn.hsh, n, output["value"], None)
        # ok, transaction is coming in order, add to DB and be done
        db[txn.handle] = txn
        return

    if len(opreturn_data) != 64:
        # a single SHA256 hash is expected
        log.error("Transaction %s does not contain valid OP_RETURN data.", txn.handle)
        return

    tok_handle = "TOK_"+opreturn_data  # handle to look for in DB
    if tok_handle not in db:
        log.error("Transaction %s contains unknown OP_RETURN data. Please import token transaction first.", txn.handle)
        return

    toktxn =db[tok_handle]

    # check that the addresses for the signatures on the token transaction matching the signatures for the inputs of
    # the BCH transaction
    tok_addrs = set(toktxn.signed_addresses)

    bch_addrs = set()
    for inp in txn.decoded["ins"]:
        point = inp["outpoint"]
        txhsh, outnum = point["hash"], point["index"]

        if "BCH_"+txhsh not in db:
            log.error("Missing BCH transaction input %s:%d.", txhsh, outnum)
            return
        else:
            out = db["BCH_"+txhsh].decoded["outs"][outnum]
            addr = bitcoin.script_to_address(out["script"])
            bch_addrs.add(addr)

    if tok_addrs != bch_addrs:
        log.error("Signatures for BCH transaction %s mismatch those for the token transaction %s.", txn.handle, toktxn.handle)
        log.error("Signed addresses for token transaction: %s", repr(tok_addrs))
        log.error("Signed addresses for BCH transaction: %s", repr(bch_addrs))
        return

    if len(toktxn.outputs) != len(txn.decoded["outs"])-1:
        log.error("Token transaction needs to have the same number of outputs as the BCH transaction minus one (for OP_RETURN).")
        log.error("Token outputs: %s", repr(toktxn.outputs))
        log.error("BCH outputs: %s", repr(txn.decoded["outs"]))
        return

    # calculate input values, taking minted tokens with CREATE into account
    valuesum = 0
    for mint in toktxn.mints:
        chainprevtxid, chainprevout, value = mint
        key = "UNSPENT_"+chainprevtxid+("_%d" % chainprevout)

        if key not in db:
            log.error("Unspent output %s:%d referenced in create not in DB.\n",
                      chainprevtxid, chainprevout)
            return

        utxo = db[key]
        if utxo.value is not None:
            log.error("Trying to create a token from non-blank output %s:%d.\n",
                      chainprevtxid, chainprevout)
            return

        if utxo.token_addr != toktxn.token_addr:
            log.error("Trying to create a token from blank output with wrong address %s:%d\n", chainprevtxid, chainprevout)
            return

        if value < 0:
            log.error("Trying to create negative number of tokens.\n")
            return
        valuesum += value
        log.info("Adding mint value %d, total %d", value, valuesum)

    for inp in txn.decoded["ins"]:
        txid = inp["outpoint"]["hash"]
        outnum = inp["outpoint"]["index"]

        key = "UNSPENT_"+txid+("_%d" % outnum)
        if key not in db:
            log.error("Missing unspent output %s:%d.", txid, outnum)
            return

        utxo = db[key]

        if utxo.value is not None:
            if utxo.token_addr != toktxn.token_addr:
                log.error("Input token address mismatch %s vs. %s.", utxo.token_addr, toktxn.token_addr)
                return

            valuesum += utxo.value
            log.info("Adding input value %d, total %d", utxo.value, valuesum)

    for value in toktxn.outputs:
        valuesum -= value
        log.info("Subtracting output value %d, total %d", value, valuesum)

    if valuesum <0:
        log.error("Transaction %s trying to overspend.", toktxn.handle)
        return

    for value in toktxn.outputs:
        if value < 0:
            log.error("Trying to create negative output")
            return

    # consume inputs,
    for inp in txn.decoded["ins"]:
        txid = inp["outpoint"]["hash"]
        outnum = inp["outpoint"]["index"]

        key = "UNSPENT_"+txid+("_%d" % outnum)
        del db[key]

    # create outputs
    for n, value in enumerate(toktxn.outputs):
        key = "UNSPENT_" + txn.hsh+("_%d" % n)
        if key in db:
            log.error("Internal error, output exists.")
            return

        out = txn.decoded["outs"][n]
        script = out["script"]
        addr = bitcoin.script_to_address(script)
        if value > 0:
            db[key] = UnspentOutput(toktxn.token_addr,
                                    txn.hsh, n, out["value"], value)
        else:
            db[key] = UnspentOutput(addr,
                                    txn.hsh, n, out["value"], None)

    # and put onchain txn into DB
    db[txn.handle] = txn


# FIXME: the whole "OO model" here is quite broken...
def process(txn):
    log.info("Processing transaction: %s", txn.handle)
    if isinstance(txn, TokenTransaction):
        processToken(txn)
    elif isinstance(txn, OnchainTransaction):
        processOnchain(txn)
    else:
        raise Exception("Invalid object %s." % repr(txn))
