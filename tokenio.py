import bitcoin
import codecs
import sys
import logging
log = logging.getLogger(__name__)

def hexlify(b):
    return codecs.encode(b, "hex").decode("ascii")

class TokenTransaction:
    def __init__(self, token_addr, mints, outputs, privs=None,
                 linked_onchain_txn = None, signatures=[]):
        self.token_addr = token_addr
        self.mints = mints
        self.outputs = outputs
        self.privs = privs
        self.linked_onchain_txn = linked_onchain_txn
        self.signatures = signatures

        msg = self.txn_part()
        log.info("Token transaction part hash: %s", hexlify(bitcoin.electrum_sig_hash(msg)))

        if self.privs is None:
            assert(len(self.signatures))
            self.signed_addresses=[]
            for sig in self.signatures:
                addr_reconstructed = bitcoin.pubtoaddr(bitcoin.ecdsa_recover(msg, sig))
                self.signed_addresses.append(addr_reconstructed)
        else:
            self.signed_addresses=[bitcoin.privkey_to_address(priv) for priv in privs]

        import io
        b = io.BytesIO()
        self.write(b)
        self.hsh = bitcoin.sha256(bytes(b.getbuffer())[:-1]) # TOTAL hash, including signatures, but excluding final \n byte
        self.handle = "TOK_"+self.hsh
        log.info("Token transaction overall hash: %s", self.hsh)


    def txn_part(self):
        s="TOKEN %s\n" % self.token_addr
        for mint in self.mints:
            chainprevtxid, chainprevout, value = mint
            # declare that output so and so (that has to be to a P2PKH for self.token_addr)
            # is worth so and so many tokens.
            s+="CREATE %s %d %d\n" % (chainprevtxid, chainprevout, value)

        for value in self.outputs: # as many outputs as in the BCH transaction that links this data, in the same order
            s+="OUT %d\n" % value
        return s

    def write(self, outfile):
        s = self.txn_part()
        outfile.write(s.encode("ascii"))

        if self.privs is not None:
            self.make_sigs(outfile, bitcoin.electrum_sig_hash(self.txn_part()))
        else:
            # write stored signatures
            for sigline in self.signatures:
                outfile.write(b"SIG ")
                outfile.write(sigline.encode("ascii"))
                outfile.write(b"\n")
        outfile.write(b"\n")

    def make_sigs(self, outfile, shash):
        """ Make and write signatures to the given output file. """
        for priv in self.privs:
            sig = bitcoin.encode_sig(*bitcoin.ecdsa_raw_sign(
                shash, priv))
            outfile.write(("SIG "+sig+"\n").encode("ascii"))

class OnchainTransaction:
    """ Representation of on-chain transactions. """
    def __init__(self, hexstr):
        self.hexstr= hexstr
        self.decoded = bitcoin.deserialize(hexstr)
        self.hsh = bitcoin.txhash(hexstr)
        self.handle = "BCH_"+self.hsh
    def write(self, output):
        output.write(b"BCH ")
        output.write(self.hexstr.encode("ASCII")+b"\n\n")

def Reader(infile):
    """ Read a stream consisting of token transactions and/or Bitcoin transactions.
    Token transactions are assumed to be a row of serialized strings starting with '@' and ending with a
    base64-encoded signature, like produced from the above code. Bitcoin transactions are assumed to have been
    validated on the chain and come from a trustworthy source.
    Returns a stream of TokenTransaction and OnchainTransaction objects. """

    while True:
        l = infile.readline().decode("ascii")
        ls = l.split()
        if not len(l):
            return
        if not len(ls):
            continue

        if ls[0] == "TOKEN": # token transaction start
            if len(ls) != 2:
                raise Exception("Read error, expected token origin address (got %s)." % l)

            # FIXME: filter!!
            token_addr = ls[1]
            mints, outputs = [], []
            sigs = []

            while ls[0] != "SIG":
                l = infile.readline().decode("ascii")
                ls = l.split()

                if ls[0] == "CREATE":
                    if len(ls) != 4:
                        raise Exception("Read error, expected CREATE parameters (got %s)." % l)

                    chainprevtxid, chainprevout, value = ls[1:]
                    chainprevout = int(chainprevout)
                    value = int(value)
                    mints.append((chainprevtxid, chainprevout, value))
                elif ls[0] == "OUT":
                    if len(ls) != 2:
                        raise Exception("Read error, expected OUT value parameter (got %s)." % l)
                    value = int(ls[1])
                    outputs.append(value)

            while len(ls):
                if ls[0]!="SIG":
                    raise Exception("SIG line expected.")

                if len(ls) != 2:
                    raise Exception("Read error, expected SIG parameters (got %s)." % l)
                sig = ls[1]

                sigs.append(sig)
                l = infile.readline().decode("ascii")
                ls = l.split()

            tt = TokenTransaction(token_addr,
                                   mints, outputs, signatures=sigs)
            log.info("Read transaction %s.", tt.handle)
            for addr in tt.signed_addresses:
                log.info("Signed with key for address: %s", addr)
            yield tt

        elif ls[0] == "BCH": # on chain transaction hex string
            yield OnchainTransaction(ls[1])


# FIXME: replace this garbage with unit tests
if __name__ == "__main__":
    priv = bitcoin.sha256("0")
    priv2 = bitcoin.sha256("1")
    addr = bitcoin.privkey_to_address(priv)
    mints = [("txid1", 0, 50),
               ("txid1", 1, 100)]
    ctxn = TokenTransaction("TOK", addr, mints, [], [priv])
    ctxn.write(sys.stdout.buffer)

    #inputs = [("txid2", 0), ("txid3", 1)]
    outputs = [30, 50]
    mtxn = TokenTransaction("TOK", addr, [], outputs, [priv2, bitcoin.sha256("2")])
    mtxn.write(sys.stdout.buffer)
