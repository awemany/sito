#!/usr/bin/env python3
import argparse
import pprint
import tokenval
import tokenio
import shelve
import bitcoin
import logging
import codecs
import tokenmove
from sys import stdin, stdout

log = logging.getLogger(__name__)

def pp(value):
    pprint.PrettyPrinter().pprint(value)

def cmdBalances(args):
    log.info("Fetching balances")
    balances = tokenval.getBalances()
    pp(balances)

def cmdProcess(args):
    for txn in tokenio.Reader(stdin.buffer):
        log.info("Processing %s.", txn)
        tokenval.process(txn)

def cmdNameToken(args):
    regtok = tokenval.RegisteredToken(args.addr, args.tokenid)
    tokenval.db[regtok.handle] = regtok

def cmdImportPrivs(args):
    for l in stdin:
        ls = l.split()
        for x in ls:
            try:
                privkey = bitcoin.b58check_to_hex(x)
                addr = bitcoin.privkey_to_address(privkey)
                tokenval.db["PRIVKEY_"+addr] = privkey
            except:
                pass

def cmdListPrivs(args):
    addrs = []
    for key in tokenval.db:
        if key.startswith("PRIVKEY_"):
            addrs.append(key[len("PRIVKEY_"):])
    pp(addrs)

def cmdListDB(args):
    pp(list(tokenval.db.keys()))

def cmdDelete(args):
    for k in args.key:
        if k in tokenval.db:
            del tokenval.db[k]
        else:
            print("Key %s not in DB.", k)

def cmdExport(args):
    for k in args.key:
        if k in tokenval.db:
            txn=tokenval.db[k]
            txn.write(stdout.buffer)
            stdout.buffer.flush()
        else:
            print("Key %s not in DB.", k)

def cmdMove(args):
    outputs = [(x.split(":")[0], int(x.split(":")[1])) for x in args.out]
    change = args.change
    tokenid = args.tokenid

    toktxn, octxn = tokenmove.moveTokens(
        tokenid,
        outputs,
        change)
    if toktxn is not None and octxn is not None:
        toktxn.write(stdout.buffer)
        octxn.write(stdout.buffer)
        stdout.buffer.flush()
        stdout.flush()

if __name__ == "__main__":
    tokenval.set_db(shelve.open("test.db"))
    try:
        parse = argparse.ArgumentParser()

        parse.add_argument("--debug", action='store_true', default=False)

        sub = parse.add_subparsers()

        parse_balances = sub.add_parser('balances', help='Show an overview of token balances')
        parse_balances.set_defaults(func=cmdBalances)

        parse_process = sub.add_parser('process', help='Load and process token or BCH transactions')
        parse_process.set_defaults(func=cmdProcess)

        parse_nametoken = sub.add_parser('name-token', help='Name a token')
        parse_nametoken.add_argument("addr", type=str)
        parse_nametoken.add_argument("tokenid", type=str)
        parse_nametoken.set_defaults(func=cmdNameToken)

        parse_importprivs = sub.add_parser('import-privs', help='Import private key(s) from stdin (DANGER!)')
        parse_importprivs.set_defaults(func=cmdImportPrivs)

        parse_listprivs = sub.add_parser('list-privs', help='List addresses for known private keys')
        parse_listprivs.set_defaults(func=cmdListPrivs)

        parse_move = sub.add_parser('move', help='Move monmey, creating token and BCH transactions. Can also create new tokens if blank inputs are available.')
        parse_move.add_argument("tokenid", type=str, help="The token ID (name)")
        parse_move.add_argument("change", type=str, help="Change address")
        parse_move.add_argument("--out", type=str, action='append', help="A destination in the form of address:amount", required=True)
        parse_move.set_defaults(func=cmdMove)

        parse_listdb = sub.add_parser('list-db', help='List keys in DB')
        parse_listdb.set_defaults(func=cmdListDB)

        parse_delete = sub.add_parser('delete', help='Delete item from DB')
        parse_delete.add_argument("key", type=str, action='append')
        parse_delete.set_defaults(func=cmdDelete)

        parse_export = sub.add_parser("export", help='Export transactions')
        parse_export.add_argument("key", type=str, action='append')
        parse_export.set_defaults(func=cmdExport)

        args = parse.parse_args()

        if args.debug:
            logging.basicConfig(level=logging.DEBUG)

        if "func" in args:
            args.func(args)
        else:
            print("You need to call one of the available subcommands.")
    finally:
        tokenval.db.close()
