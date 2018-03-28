# SITO - A SImple TOken system by `/u/awemany`

`sito` is arguably the simplest, yet "decentralized" token system for BCH one can think of.

This is the result of a recurring discussion on the "Gold Collapsing, Bitcoin Up!" (GCBU) thread on the [bitco.in](http://bitco.in/forum) forum on the merits and drawbacks of different tokenization schemes for Bitcoin/BCH, spurring an investigation into this simple "extra meta data" approach. Bitcoin/BCH/Cash will simply be referred to as Bitcoin henceforth herein.

The ideas presented here are very simple, almost embarassingly so. Similar systems have very likely sprung up in the past and the author is happy for any pointers provided to similar efforts!

__Very important notice__: This is all still in the *proof-of-concept* stage! The code examples below are working and should be just enough to show a clear path on how this token system can work at larger scale and more fully integrated on Bitcoin. It should also be enough inspiration to maybe invite others to help to work or base their work on this as well as to roughly evaluate the strengths and weaknesses of this approach for building tokens on top of Bitcoin and compare it to other solutions like OP_GROUP.


__By no means is this even remotely complete and NO ONE should risk any amount of money he or she is not absolutely willing to lose using this system! This software comes with NO WARRANTY whatsoever. It IS full of bugs.__

It should be noted that I didn't get around to implement `cashaddr` for this yet, so expect old-style addresses.

## Overview

`sito` is meant as a token scheme on top of Bitcoin Cash, to allow for decentralized exchange and tracking of various tokens, such as stocks or other financial instruments, to allow their free exchange much like money after they have been initially created, without any further action by the issuer/"mint".

Tokens can be generated by anyone, but in the context of `sito`, they are uniquely referred to by the Bitcoin public-key address generating them (Different address schemes might be viable in the future, but this has not been investigated yet).

After tokens have been created and leave the hands of the creator, they can be freely exchanged just like Bitcoin, albeit with tracking of some extra, off-chain data by the parties involved in the transfer.

The main goal of `sito` is to simple. For this reason

- it does not introduce any meta currency
- nor introduces any changes to the current Bitcoin protocol
- nor uses any fancy features of the script language (just a simple OP_RETURN data tag)
- it keeps almost all of the neccessary extra data off the chain


## Design overview

The core idea is straight forward: Use OP_RETURN to attach the minimum amount of off-chain metadata to transactions and track the transfer of tokens by means of a combined *token transaction* on a *tokenchain* or *token ledger* (one such chain for each token, which in reality is a DAG) plus a regular transaction on the Bitcoin blockchain.

### Transaction format

Much like Bitcoin, token transaction are using inputs and outputs.

**The key idea is that the meta data for the token chain is structured such that Bitcoin inputs/outputs become token inputs/outputs as well.**

This ensures that by tracking the state of the Bitcoin chain, the eventual balances in the token chain are known and unique as well.

Instead of having just BCH moving in a transaction like this:

[BCH txn: IN\_0, IN\_1, IN\_N, OUT\_0, OUT\_1, ... OUT\_M]

it changes the transaction interpretation so that tokens as well as BCH are moved in chains of combined transactions like this:

[BCH-TOK txn: IN\_0, IN\_1, IN\_N, OUT\_0, OUT\_1, ... OUT\_M]

Having the same structure above is no mistake. As said, each point (inpoint/outpoint) of a token transaction and each Bitcoin point are intertwined for tokens corresponding to this chain.

The token data in each of the above combined transactions is put into a separately signed token transaction:

[TOK txn\_i: IN\_0, IN\_1, IN\_N, OUT\_0, OUT\_1, ... OUT\_M]

Let the 20-byte SHA256 hash of this signed transaction be H.
and is then referred to in a Bitcoin transaction with an OP_RETURN:

[BCH txn\_i: IN\_0, IN\_1, IN\_N, OUT\_0, OUT\_1, ... OUT\_M, OP_RETURN 0x20 H]

Token transactions are to be deemed valid only when both the TOK as well as the BCH transaction parts are valid and when both transactions are signed with the same set of keys. Currently, only P2PKH transactions are supported by the proof of concept code in `sito` and for simplicity, no extra scripting or similar functionaly has been implemented in the token transaction scheme (and is also deemed unnecessary). The main part of token validation is to obviously check that the value of token\_inputs-token\_outputs is a value larger or greater than zero. Token amounts are currently simple integers, but should be assumed to be limited to 64-bit amounts (an important detail which is not implemented yet). There is no relation between the amount of tokens and amount of Satoshis transacted on the BCH chain, and therefore outputs above the dust limit should suffice for tracking tokens in the BCH UTXO set.

### Token creation

Tokens are created by spending from their corresponding *token address*. It is by this token address that different tokens are separated from each other in the system and how token issuance is controlled. Naming a token is separate, fully decentralized step in `sito`, which will just give a short handle to what is, in terms of validation, always a particular token address (and the corresponding pub/priv key pair, of course).

If desired, any agreed-upon issuance schedule of a token can be checked by summing the outputs that moved Bitcoins from that particular address.

In `sito`, tokens to be generated from an address have to be made from a Bitcoin transaction that does *not* include an OP_RETURN and which create what is internally referred to in sito as *blank UTXOs*. Blank UTXOs are outputs which have no amount of any tokens associated with them and can be used to generate any amount of tokens (unless limited by further social contracts / conventions) of the "color" determined by the P2PKH address in their respective spend script.
This limits the token creation to the owner of the private key corresponding to this token address.

It is a good idea of course, to replace this cumbersome token address with a short handle ("tokenid"). It should be noted that the naming of tokens is completely decentralized and no "DNS system" (or variants like namecoin) for token namings is part of `sito`'s core functionality. If one is not careful, collisions of token handles may thus happen.

After minting with an initial token transaction referring to such a blank input and with a special creation marker and finishing the full transaction by crafting the corresponding Bitcoin transaction, the tokens can then be moved using the TOK+BCH transaction combinations.

### Destruction

As `sito` only checks the condition that `token_inputs - token_outputs >=0`, tokens can be destroyed. Corresponding transactions can therefore be seen as a "proof of burn". Alternatively, tokens can be destroyed by spending them in regular transactions - which the author did with the test coins used below.

## `sito` the proof-of-concept program: Dependencies and requirements

`sito` is a python3 program. It needs the BCH fork of `pybitcointools`, which be downloaded and installed from here: [https://github.com/Conio/pybitcointools](https://github.com/Conio/pybitcointools)

After the `git clone`, the `bitcoincash` branch MUST be checked out from that repository, like so:

`git checkout -m bitcoincash origin/bitcoincash`

It can then be installed for the current user by doing:

```
$ python3 setup.py install --user
```

from within a `git` checkout of the above repository. Currently, `sito` does not need any other python packages. This installation assumes that no other package under the import name `bitcoin` exists yet. If it does, the user has to adequately insure that `sito` accesses the correct `pybitcointools` library.

## Example run of `sito`

An example run of the rudimentary `sito` command line tool and the manual movement of a couple tokens is shown below, to give the general idea on how this all supposed to work. At the moment `sito` works by operating on a python-specific key value database named `test.db` in the current working directory, so be aware of that :-).

For these tests, an Electron Cash instance has been used to extract and inject the corresponding Bitcoin transactions from and to the Blockchain, and to ensure that only verified transactions enter the `sito` database. The corresponding wallet has since been emptied and the seed value for this test wallet was:

```illness pond panther two ethics hole during weather stamp mix hazard dragon```

This seed can be used to examine the execution of the example commands below.

### Create blank UTXO
First of all, a BCH transaction is imported. This creates an unspent *BCH* output in `sito`'s database that is tied to address `1PrWqTgCo1C7MCMHedUXjZpjZU7UJAcf9P` (it creates another one which will not be of further interest here, as it the change address of the /u/tippr bot the author used to withdraw a millibch into a fresh wallet for testing...). Both token as well as BCH transactions are imported using the `process` subcommand, which expects BCH transactions in hex, prefixed with `BCH` on standard input, or token transactions in their default ASCII format:

`$ ./sito process`

```
BCH 020000000...
```

(The transaction can be exported from Electron Cash in the transaction detail view and clicking on the copy button in the lower left corner)

By prepending the subcommand with the `--debug` flag, the code becomes very noisy and will print a lot of debugging information to make it easier to spot errors when using it as well as the inevitably numerous bugs in the current codebase.

Note that `sito` does NOT check the validity of BCH transactions and assumes that their source is trustworthy, in the sense that they have been fully validated and written into the blockchain. (Or if not written into the blockchain yet, that their 0-conf confidence is sufficiently high).

### Naming the token and showing the token balance(s)

The unspent output on `1PrWqTq...` is meant to be the token TOK from here on, so let's name this in `sito` and give it the very imaginative name `TOK`:

```
$ ./sito name-token 1PrWqTgCo1C7MCMHedUXjZpjZU7UJAcf9P TOK
```

As said, `sito` uses a (too) simple key value store at the moment, of which the keys can be listed like this:

```
$ ./sito list-db
```

```
['UNSPENT_8fede24d19c0e11bd75ef60a88a4f4ac3a5bb2bb330139dcbeb21fddd44f9b80_1',
 'TOKEN_1PrWqTgCo1C7MCMHedUXjZpjZU7UJAcf9P',
 'UNSPENT_8fede24d19c0e11bd75ef60a88a4f4ac3a5bb2bb330139dcbeb21fddd44f9b80_0',
 'BCH_8fede24d19c0e11bd75ef60a88a4f4ac3a5bb2bb330139dcbeb21fddd44f9b80']
```

Which shows the token address -> token id mapping with `TOKEN_1Pr...`, the imported BCH transaction and the two unspent outputs.

The balance of all outputs for all known tokens can be printed with this:

`$ ./sito balances`

`{'TOK': 0}`

Balance is meant here as the TOK tokens that can actually be spent and have a private key available for spending.

### Import keys

To be able to produce valid token transaction and Bitcoin transactions (be fully aware of all the danger that comes with this!), `sito` supports import of a set of base58-encoded private keys on standard input, using the `import-privs` subcommand. So the exported private keys from Electron Cash (just copy them from the export window, the import ignores data that isn't private keys) can be imported on `stdin` like this:

`$ ./sito import-privs`

`<long list of privkeys>`

### Create and tokens

`sito` now has all the necessary data available to sign a token transaction. Assume we want to send 500 TOK to `1NGPGz3FJJ4YfVyb63CTqneYQPFY2oaVoE` and 1000 TOK to `15uzuVXVotRKt5qk89coGCxN5TjVxw2LyE`. Further assume that any Bitcoin or TOK change we might have should go to change address `1GSsPvRB7jdoTqwDuX7QngpHTnqqqQc5Y7` (to keep with electron cash's scheme). The command to generate this transaction is:

`$ ./sito move --out 1NGPGz3FJJ4YfVyb63CTqneYQPFY2oaVoE:500 --out 15uzuVXVotRKt5qk89coGCxN5TjVxw2LyE:1000 TOK 1GSsPvRB7jdoTqwDuX7QngpHTnqqqQc5Y7`

`TOKEN 1PrWqTgCo1C7MCMHedUXjZpjZU7UJAcf9P`

`CREATE 8fede24d19c0e11bd75ef60a88a4f4ac3a5bb2bb330139dcbeb21fddd44f9b80 0 1500`

`OUT 500`

`OUT 1000`

`OUT 0`

`SIG IK8O157RyFmskTHE82ogOb/LOC+zubOmiK2CE9f3Xrz5G4JhaNaWfAV3s+OHVa1Pc7uQYqQ+5I3JiVDAiLxWtB0=`


`BCH 0100...`

Which creates the token transaction first, followed by the signed and ready BCH transaction and prints both on `stdout`.

#### The token transaction

The `TOKEN` line identifies the token that this transaction moves. The `CREATE`
line afterwards refers to an outpoint of a blank BCH UTXO (hash and outpoint number) and the number of tokens to create (1500). As the inputs are not all listed in a token transaction, the outpoint used here is explicitly referenced.

This is followed by three `OUTPUT` lines, which correspond to the outputs of the BCH transaction in the same order and is to be interpreted as funding those three outputs (the two outputs given with the `--out` parameter plus the change output) with 500, 1000 and 0 TOK, respectively.

Note that, due to their minimum amount of information, circumstances may occur where token transactions could be replayed as-is! But because they are only deemed valid in unison with a corresponding BCH transaction, any potential replay attacks of this kind should be properly addressed.

#### The BCH transaction
Upon closer inspection, the ```6a20``` marker, corresponding to the `[OP_RETURN 0x20]` opcode sequence is visible in the BCH transaction, refering to the SHA256 hash `0x20dbf3..` of the token transaction part, which can also be checked by running the token transaction ASCII serialization through the `sha256sum` command line tool.

It should be noted here that the `move` command is used both for initial "minting" of new tokens as well as for transferring existing tokens and is the equivalent to a Bitcoin wallet's send function. It auto-selects token and BCH inputs to build the combined BCH-TOK transaction in a process, that, well could be vastly improved.

Sito does NOT change its UTXO set after signing a transaction (which can be checked with `sito balances`) and a separate call to the `process` subcommand has to be done to actually change its internal state:

`$ ./sito process`

`TOKEN ...`

`BCH ...`


`$ ./sito balances`

`{'TOK': 1500}`

Of course, this state is not reflected on the Blockchain yet and the BCH transaction should be loaded into `electron-cash` and broadcast, if that is desired. If you load it there, you'll notice that most of the incoming 100000 satoshis move to the change address and the two token outputs are funded with just a 1000 satoshi each to be above the dust limit.

Some of these tokens can then be moved further, listing an output and another change address:

`$ ./sito move --out 1LVNTFe81fsoPnNHk8M9teNhAUpiQXrdsQ:300 TOK 1P8dQbjvM2gwLLAEWo7uW9Gc989xJNG9MG`

`TOKEN 1PrWqTgCo1C7MCMHedUXjZpjZU7UJAcf9P`

`OUT 300`

`OUT 700`

`SIG H273uq0UecogF/LffZsxKPXvc9gfTcFK9Qc6nLr9A8wXKDw55rbZgTmio++Y74Wb72w2tXR/G8ezTuJL+ieptdI=`

`SIG IF7pPKx1CDEAmv8t8ejW/P7DV9zc6rBZFr/hvkfhDP9YV8ruEcm/UiDklRBu179fRDuwk9+Xfvn4GAIGCJHaEQA=`

`BCH 0100..`

This time, the transaction has two inputs and two outputs (plus the OP_RETURN), to account for the necessary miner fee input as well the change output. As enough tokens are available for use, it does not issue new tokens.

And again, the generated transactions have to be applied using the `process` subcommand.

... and so forth!

## Future

Again, this is all just proof of concept, so the software is rather a collection of holes to fill rather than a serious set of tools. However, if folks like this approach sufficiently well enough, these are my ideas for further work to make this "complete":

- proper DB for UTXOs and other items (likely SQLite with some indexes is a good choice here for now)
- proper wallet integration (electroncash)
- proper spending, privacy, good coin selection support
- protocol and implementation for synchronizing of tokenchains to selectable servers and/or P2P to other users, HTTP is likely a good idea for simplicity
- binary message format
- proper command line interface
- web-server style GUI
- port the key parts to Java for cellphone wallets
- proper BCH fee selection and change generation

## Thanks

Thanks to Christoph Bergmann on bitco.in for the initial discussion out of which came the inspiration to create this proof of concept and everyone else on bitco.in for the inspiring discussions. And of course everyone who's libraries I am building upon and the greater Bitcoin Cash community.
