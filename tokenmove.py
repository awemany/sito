# wallet functionality. create transactions to move tokens per spec
import logging
import tokenio
import tokenval
import bitcoin
import codecs
log = logging.getLogger(__name__)

def takeUtxo(utxo, privs, bch_inputs, skip_if_blank=False):
    """ Take UTXO for spending and update the input arrays and private key set for later signing. """
    intxhsh = utxo.txhash
    log.info("Looking at UTXO %s.", utxo)
    if "BCH_" + intxhsh not in tokenval.db:
        log.info("Input transaction missing for UTXO %s.", utxo)
        return None, None

    intx = tokenval.db["BCH_" + intxhsh]

    bch_prevout = intx.decoded["outs"][utxo.outnum]
    bch_prevout_addr = bitcoin.script_to_address(bch_prevout["script"])
    priv = tokenval.privKey(bch_prevout_addr)

    if priv is None:
        log.info("Private key not available for unspent output %s.",
                 utxo)
        return None, None

    log.info("Taking unspent output %s.", utxo)

    if not skip_if_blank or utxo.value is not None:
        privoutpoint = utxo.txhash+":"+str(utxo.outnum)
        privs[privoutpoint]=priv

        bch_inputs.append(
            { "output" : privoutpoint,
              "amount" : utxo.bch_value})

    return utxo.value, utxo.bch_value


def moveTokens(
        tokenid,
        outputs,
        change):
    """ move given amount of tokens to given outputs.
    tokenid: name of the token to deal with
    outputs is a list of (output, amount) pairs.
    change is the receiving address for change.
    Returns a pair (TokenTransaction, OnchainTransaction) or None if an error occured.
    Does not change the DB.

    Autocreates a mint transaction if the outputs exceed the available funds and there is a blank output plus the corresponding private key available.
    """
    log.info("Trying to move %s tokens to %s outputs plus one change address", tokenid, len(outputs))
    token_addr = tokenval.tok2addr(tokenid)

    for x in outputs:
        if x[1] < 0:
            log.error("Negative outputs not allowed.")
            return None, None

    # total needed amount of tokens
    needed = sum(x[1] for x in outputs)
    log.info("Total needed amount of tokens: %d", needed)

    # sum of incoming BCH satoshis
    bch_insum = 0

    # sum on incoming tokens
    token_insum = 0

    utxo_avail = tokenval.unspentOutputsForToken(token_addr)
    log.info("Known UTXOs for token %s: %d.", tokenid, len(utxo_avail))
    # collect enough inputs until we've got everything we need
    privs = {}

    mints = []
    bch_inputs = []
    bch_outputs = []

    for utxo in utxo_avail:
        value, bch_value = takeUtxo(utxo, privs, bch_inputs, skip_if_blank=True)
        if value is None or bch_value is None:
            log.info("Skipping UTXO %s.", utxo)
            continue
        token_insum += value
        bch_insum += bch_value
        if token_insum >= needed:
            break

    log.info("Collected %d inputs for a total of %d %s and %d satoshis.",
             len(bch_inputs), token_insum, tokenid, bch_insum)

    if token_insum < needed:
        # FIXME: code dup
        log.info("Less tokens %d available than needed %d.", token_insum, needed)
        blank = tokenval.unspentBlank(token_addr)
        if blank is None:
            log.error("And no blank outputs are available to create new tokens.")
            return None, None
        value, bch_value = takeUtxo(blank, privs, bch_inputs)

        assert(value is None)
        if bch_value is None:
            log.info("Blank could not be taken.")
            return None, None
        mints.append((blank.txhash, blank.outnum, needed-token_insum))
        log.info("Taking blank unspent output %s and minting %d %s.",
                 blank,
                 needed-token_insum, tokenid)

        token_insum += needed-token_insum
        bch_insum += bch_value

    l = len(outputs) + 1 # +1 for change output

    miner_fee = 200 * l # total miner fee for transaction

    min_funds = 1000

    log.info("Total miner fee: %d", miner_fee)

    if bch_insum < l*min_funds + miner_fee: # 1 satoshi per token output plus miner fee available
        log.info("Needing extra inputs for miner fees, having %d satoshis and needing %d satoshis.", bch_insum, l*min_funds+miner_fee)
        for utxo in tokenval.allUnspentOutputs():
            if ("TOKEN_"+utxo.token_addr in tokenval.db) or utxo.value is not None:
                log.info("Skipping UTXO %s as it is a token output.", utxo)
                continue
            value, bch_value = takeUtxo(utxo, privs, bch_inputs)
            assert(value is None)
            if bch_value is None:
                continue
            bch_insum += bch_value
            if bch_insum >= l*min_funds + miner_fee:
                break
    if bch_insum < l*min_funds + miner_fee: # 1 satoshi per token output plus miner fee available
        log.info("Not enough extra inputs available, having %d satoshis and needing %d satoshis",
                 bch_insum, l*min_funds + miner_fee)
        return None, None

    tok_outputs=[]

    for out in outputs:
        addr, val =  out
        bch_outputs.append({"value" : min_funds,
                            "address" : addr })
        log.info("Adding output %s with %d tokens.", addr, val)
        tok_outputs.append(val)

    bch_outputs.append({"value" : min_funds + bch_insum - miner_fee - l*min_funds,
                        "address" : change })
    log.info("Adding output %s with %d tokens.", change, token_insum-needed)
    tok_outputs.append(token_insum-needed)

    log.info("Token mints: %d", len(mints))
    log.info("Token outputs: %d", len(outputs))
    toktxn = tokenval.TokenTransaction(token_addr,
                                     mints, tok_outputs, list(privs.values()))

    log.info("BCH transaction inputs: %s", bch_inputs)
    log.info("BCH transaction outputs: %s", bch_outputs)

    bchtxn = bitcoin.mktx(bch_inputs, bch_outputs)
    log.info("Created unsigned BCH transaction.")
    bchtxn = bitcoin.transaction.mk_opreturn(codecs.decode(toktxn.hsh, "hex"),
                                             bchtxn)
    log.info("Added OP_RETURN pointer.")

    for i, bch_in in enumerate(bch_inputs):
        prevoutstr = bch_in["output"]
        # bch_inputs.append(
        #     { "output" : prevoutstr,
        #       "amount" : utxo.bch_value})

        log.info("Signing BCH input %d: %s", i, bch_in)
        bchtxn = bitcoin.segwit_sign(bchtxn, i, privs[prevoutstr], bch_in["amount"],
                                     hashcode=bitcoin.SIGHASH_ALL | bitcoin.SIGHASH_FORKID, separator_index=None)

    octxn = tokenval.OnchainTransaction(bchtxn)

    return toktxn, octxn
