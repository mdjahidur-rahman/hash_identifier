# Hash Identifier

A small Python command-line tool that identifies what kind of hash a string is. Give it a hash, and it prints the most likely algorithm, how confident it is, and why.

Built while learning cybersecurity fundamentals — identifying a hash is the first step before choosing the right cracking tool.

## How it works

The `identify()` function runs the input through 6 checks, most specific first. The first check that matches returns:

1. **Known prefixes** — `$2b$`, `$argon2id$`, `$6$`, and 9 more. A matching prefix means high confidence.
2. **Special formats** — NetNTLMv1/v2, MySQL5 (`*` + 40 upper hex chars), DES crypt (13 chars).
3. **Hex + length** — a 32-character hex string could be MD5, NTLM, MD4, or RIPEMD-128. They look identical, so the first is ranked medium and the rest low.
4. **Generic PHC strings** — anything shaped like `$name$...` that no earlier rule matched.
5. **Non-hashes** — JWTs and Base64 blobs are flagged as "not a hash" instead of being misidentified.
6. **No match** — returns nothing, and the CLI prints "No identification possible."

All the known formats live in data tables (`PREFIX_RULES`, `HEX_LENGTH_RULES`), not in if/else chains — so adding a new format is one new row, with no change to the logic.

## Run it

No installs needed. Python 3.10+.

```bash
python hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99
python hash_identifier.py '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G'
python hash_identifier.py --help
```

Use `--top N` to show more or fewer candidates (default 5).

## Example

```
$ python hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99
Candidates for: 5f4dcc3b5aa765d61d8327deb882cf99
algorithm            | confidence   | reason
----------------------------------------------------------------------
MD5                  | medium       | 32 hex chars — most likely candidate at this length
NTLM                 | low          | 32 hex chars — also possible at this length
MD4                  | low          | 32 hex chars — also possible at this length
RIPEMD-128           | low          | 32 hex chars — also possible at this length
```

## Tests

```bash
python test_hash_identifier.py
```

Plain asserts, no pytest needed. One test loops over every row in `PREFIX_RULES` and checks each format is recognised with high confidence, so new formats are covered automatically.
