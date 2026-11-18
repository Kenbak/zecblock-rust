# Zakura parser compatibility fixtures

Captured on 2026-09-21 JST from CipherScan's own nodes using `getblockhash` and
`getblock` (verbosity 0 and 1). Mainnet was Zakura 1.3.0; testnet was 1.4.0.
Raw blocks and RPC transaction IDs are public chain data; no credentials are stored.

The 18 blocks cover both sides of Sapling, NU5, NU6.2, and NU6.3 activation on
mainnet and testnet, plus one recent block per network. They contain 70 transactions:
11 v3, 7 v4, 22 v5, and 30 v6, including 2 Sapling spends, 4 Sapling outputs,
18 Orchard actions, and 56 Ironwood actions.

`parser-expected.json` was generated with the unchanged parser at indexer commit
`115c40a`, using Zebra tag `v6.0.0` (crate 11.1.0, commit `bb41d69013ed`). The
baseline parser source is also identical to deployed mainnet commit `1f03081`.
The new parser is Zakura tag `v1.4.0` (crate 7.0.0, commit `1e36d1bb6a8a`).
Both Linux reports were byte-for-byte identical before saving these fixtures.

Run `cargo test --locked --test parser_compatibility`. The regression checks
full-block deserialization/serialization, complete input consumption, coinbase
height, RPC block/transaction hashes, all indexed header fields, and all raw
transaction fields (scripts, transparent outputs, shielded counts/balances/anchors).
The JSON comparison decodes both reports equally to avoid a one-ULP difference
from serde_json's default floating-point parser; zatoshi amounts remain integers.

Regenerate a report with:

```sh
cargo run --locked --release --example parser-fixture-report -- tests/fixtures/parser-blocks.json
```

Do not regenerate expected results from the candidate merely to make a failing
test pass. Establish an independently reviewed baseline and investigate each change.

These fixtures do not resolve historical prevouts or prove database/fee accounting,
stream recovery, or sustained capacity. Those require separate integration and
isolated replay checks. The original corpus predates NU7; the staging supplement below adds real activation coverage. Keep historical v4 coverage.

## Real NU7 staging activation (2026-09-28 JST)

`nu7-staging-blocks.json` contains pre/activation/post blocks 4,398,755–4,398,757
from **Nu7StagingV2**, activation 4,398,756 / branch 77190ad9.
Captured using getblock verbosity 0/2 on an isolated locally validating node
built at manifest revision 738d175061e23d1ad65ec99b2d2a6b5d004bb10f.
Authority: https://api.nu7.valargroup.dev/v1/network and https://zakura.com/nu7/.
Seed height 4,398,752; SHA256 4a347a643eee9a33f0b56a0f28e365c63ffbc0d5cc4ee46cd5d7cd1929117595.
Also includes the fee-bearing block 4,400,478 (two transactions).
These are blocks from the staging fork, not official testnet/mainnet
activation certification. The test compares node block hashes, all txids and exact
serialization roundtrips through the release v1.5.0/parser 8 dependency.

## Header commitment relabelled (2026-11-18)

The baseline parser reported the header's 32-byte commitment field as
`final_sapling_root`. That name is only correct from Sapling to Heartwood; since
Heartwood the field is a chain-history or block-commitments hash. For mainnet
block 2,000,000 the header field is `e11c1c4c…bf31` while the node's
`finalsaplingroot` is `23cf0bd8…8e4b`.

`parser-expected.json` now carries those same 18 captured values under
`block_commitments`, and `final_sapling_root` is `null`: the header parser no
longer reports any tree root, which only the node can supply. This was a key
rename of the independently captured baseline, not a regeneration from the
candidate; every other expected value is byte-for-byte unchanged.
