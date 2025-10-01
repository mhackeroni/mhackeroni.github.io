---
title: "spAES-1 - Ctrl+Space Quals 2025"
date: "2025-09-30"
description: "The official writeup  for the challenge spAES-1 from the Ctrl+Space Quals 2025 CTF"
tags: ["crypto", "ctf", "ctrl", "space", "mhackeroni", "aes"]
showAuthor: false
---
Authors: Federico Cioschi <@fedec>, Matteo Rossi <@mr96>

(12 solves, 278 pt)

> Check out our new cipher, it will replace AES for space!
>
> It is safer, quicker and ready for orbit!
>
> Try our encryption service.

```sh
nc spaes-1.challenges.ctrl-space.gg 10019
```


## Overview

We have a custom SPN algorithm used with the ECB mode to encrypt a secret file. Internal operations are like AES ones, but they are based on a 4x8 matrix of nibbles. Every time we connect to the server, a 16 bytes key is generated with `os.urandom(16)`. Before the session is closed, we can only execute 2 operations among the following ones: 

```
Welcome to the super secure encryption service in-space!
    1) Encrypt text
    2) Obtain our super-secret file, you can't decrypt it!
    3) Quit
```


## Solution


### Idea

*Integral Cryptanalysis*, commonly known as *Square Attack*, is a possible way to face the challenge.

From [Wikipedia](https://en.wikipedia.org/wiki/Integral_cryptanalysis):

> In cryptography, integral cryptanalysis is a cryptanalytic attack that is particularly applicable to block ciphers based on substitution–permutation networks. [...] Unlike differential cryptanalysis, which uses pairs of chosen plaintexts with a fixed XOR difference, integral cryptanalysis uses sets or even multisets of chosen plaintexts of which part is held constant, and another part varies through all possibilities. For example, an attack might use 256 chosen plaintexts that have all but 8 of their bits the same, but all differ in those 8 bits. Such a set necessarily has an XOR sum of 0, and the XOR sums of the corresponding sets of ciphertexts provide information about the cipher's operation.

Since this cipher works on nibbles, the idea is to build deltasets with an active nibble: i.e. we vary the plaintexts among all the possible 16 values of the active nibble, and we take the remaining part of the plaintext constant. Observing the xor-sums of a deltaset across the internal rounds, we may understand which nibbles are balanced at the end of each round. With _balanced_ we mean that the xor-sum of each deltaset element on that nibble is 0. Then, we can build an attack leveraging this property.

Let's modify the encryption function to take the number of rounds as a parameter.

```py
from spaes import *

def enc_r(m, k, t, rounds):

    RCON = [bytes.fromhex(x) for x in CONSTS]
    
    state = to_matrix(m)
    key_matrix = to_matrix(k)
    tweak_matrix = to_matrix(t)

    state = [[state[i][j] ^ key_matrix[i][j] for j in range(8)] for i in range(4)]

    for r in range(rounds):
        state = [[SBOX[state[i][j]] for j in range(8)] for i in range(4)]
        state = shift_rows(state)
        state = mix_columns(state)
        round_const_matrix = to_matrix(RCON[r])
        state = [[state[i][j] ^ round_const_matrix[i][j] for j in range(8)] for i in range(4)]

        if r % 2 == 0:
            state = [[state[i][j] ^ key_matrix[i][j] for j in range(8)] for i in range(4)]
        else:
            state = [[state[i][j] ^ tweak_matrix[i][j] for j in range(8)] for i in range(4)]

    c = from_matrix(state)
    return c
```

And now we can observe which nibbles are still balanced at the end of each round if we activate the nibble `(0,0)` of the plaintext. To reduce the possibility of false positives, we use 5 different deltasets and then intersect their results.


```py
import os

DS_NUMBER = 5

def null_nibbles(s):
    m = to_matrix(s)
    return set([(i,j) for j in range(8) for i in range(4) if m[i][j]==0])

def xor_bytes(a, b):
    return bytes(i^j for i, j in zip(a, b))

def set_nibble(s,i,j,v):
    m = to_matrix(s)
    m[i][j] = v
    return from_matrix(m)

key = os.urandom(16)
i,j = 0,0

for rounds in range(1,6):
    ds_sums = list()
    for _ in range(DS_NUMBER):
        acc = b"\x00"*16
        pt_const = os.urandom(16)
        for val in range(16):
            pt = set_nibble(pt_const,i,j,val)
            ct = enc_r(pt, key, b"\x00"*16, rounds)
            acc = xor_bytes(acc, ct)
        ds_sums.append(acc)
    mapping = set.intersection(*list(map(null_nibbles, ds_sums)))
    print(f"R{rounds}: {mapping}")
```

The result is the following. As you can see, at the end of the 5th round we still have 6 balanced nibbles.

```
R1: {(3, 4), (3, 1), (3, 7), (0, 2), (0, 5), (2, 2), (1, 0), (1, 6), (2, 5), (1, 3), (3, 0), (3, 3), (3, 6), (0, 1), (0, 7), (2, 4), (1, 2), (0, 4), (2, 1), (2, 7), (1, 5), (3, 2), (3, 5), (0, 0), (1, 1), (0, 3), (2, 0), (1, 4), (0, 6), (2, 3), (1, 7), (2, 6)}
R2: {(3, 4), (3, 1), (3, 7), (0, 2), (0, 5), (2, 2), (1, 0), (1, 6), (2, 5), (1, 3), (3, 0), (3, 3), (3, 6), (0, 1), (0, 7), (2, 4), (1, 2), (0, 4), (2, 1), (2, 7), (1, 5), (3, 2), (3, 5), (0, 0), (1, 1), (0, 3), (2, 0), (1, 4), (0, 6), (2, 3), (1, 7), (2, 6)}
R3: {(3, 4), (3, 1), (3, 7), (0, 2), (0, 5), (2, 2), (1, 0), (1, 6), (2, 5), (1, 3), (3, 0), (3, 3), (3, 6), (0, 1), (0, 7), (2, 4), (1, 2), (0, 4), (2, 1), (2, 7), (1, 5), (3, 2), (3, 5), (0, 0), (1, 1), (0, 3), (2, 0), (1, 4), (0, 6), (2, 3), (1, 7), (2, 6)}
R4: {(0, 1), (0, 7), (2, 1), (2, 7), (0, 0), (3, 1), (3, 7), (1, 1), (2, 0), (3, 0), (0, 6), (1, 7), (2, 6), (0, 5), (3, 6), (1, 0), (1, 6)}
R5: {(3, 7), (0, 6), (2, 6), (0, 5), (3, 6), (1, 6)}
```

Iterating over `i` and `j` we can activate all the other nibbles in the plaintext and consequently map which nibbles of the state are balanced after the 5th round. We can exploit this to guess the last-round key, nibble by nibble. To do this, it is useful to map the position of the balanced nibbles after the shift-row operation on the 6th round, because in that position will happen the xor with the last round key. This is why we use the `shift_row_pos()` function below.

Finally, we also have a small issue: some nibbles are still balanced even after the 6th round. If we don't take care of that we may obtain false positives during the key guessing. For our exploit to work, it was enough to remove the mapping `(0,5)` for the active nibble `(0,0)`.

```py
def shift_row_pos(i,j):
    return (i,j-i if j>=i else j+8-i)

key = os.urandom(16)
tweak = b"\x00"*16
mappings = {(i,j):dict() for i in range(4) for j in range(8)}
for i,j in mappings:
    ds_sums = list()
    for _ in range(DS_NUMBER):
        acc = b"\x00"*16
        pt_const = os.urandom(16)
        for val in range(16):
            pt = set_nibble(pt_const,i,j,val)
            ct = enc_r(pt, key, tweak, 5)
            acc = xor_bytes(acc, ct)
        ds_sums.append(acc)
    mapping = set.intersection(*list(map(null_nibbles, ds_sums)))
    mapping = set(map(lambda c: shift_row_pos(c[0],c[1]), mapping))
    mappings[i,j] = mapping
mappings[0,0].remove((0,5)) # we saw this mapping generates false positives
print(mappings)
```

### Getting deltasets

After calculating the mappings locally, we must recover deltasets using the key on the server and then guess it.

We are only allowed to perform 2 operations during a session on the server, and one is needed to recover the secret file. Luckily, the ECB mode of encryption allows us to send a long plaintext containing all the elements of a deltaset, which are then encrypted in sequence. Also, we can concatenate several deltasets together in one plaintext.

```py
from pwn import remote
from base64 import b64encode, b64decode

HOST = os.environ.get("HOST", "spaes-1.challenges.ctrl-space.gg")
PORT = int(os.environ.get("PORT", 10019))

r = remote(HOST, PORT)

def remote_enc(r, pt):
    r.recvuntil(b"choice:")
    r.sendline(b"1")
    r.recvuntil(b":")
    r.sendline(b64encode(pt))
    ct = b64decode(r.recvline())
    return ct

deltasets = dict()
plaintext = b""
for i,j in mappings:
    for _ in range(DS_NUMBER):
        pt_const = os.urandom(16)
        for v in range(16):
            plaintext += set_nibble(pt_const,i,j,v)

ciphertext = remote_enc(r, plaintext)
for i,j in mappings:
    deltasets[i,j] = list()
    for dsn in range(DS_NUMBER):
        deltasets[i,j].append(list())
        for _ in range(16):
            deltasets[i,j][dsn].append(ciphertext[0:16])
            ciphertext = ciphertext[16:]

print(deltasets)
```



### Guessing the last round key

We now have a deltaset for each possible active nibble. Also, we mapped which nibbles are balanced after the 5th round for each possible active nibble.
We can now extract the last round key. 

For each nibble in the last-round key we only have to try each possible value, then use it to invert the state across the 6th round, and finally verify if the xor-sums of the balanced nibbles at round 5 are actually 0. If yes, we probably identified the correct value of the key nibble.
We repeat this for 5 deltasets, to avoid possible false positives.

```py
from functools import reduce
from spaes import inv_sbox
import operator

def from_matrix_dict(state):
    return bytes([state[i,j] << 4 | state[(i+1),j] for j in range(8) for i in (0, 2)])

def inv_round_nibble(n,kv):
    s = n ^ kv
    s = inv_sbox[s]
    return s

lrk_guess = {(i,j):None for i,j in mappings}
for i,j in mappings:
    for ki,kj in mappings[i,j]:
        if lrk_guess[ki,kj] is not None:
            continue
        for kv in range(16):
            for dsn in range(DS_NUMBER):
                ds = deltasets[i,j][dsn]
                inv_nibble_ds = [inv_round_nibble(to_matrix(ct)[ki][kj],kv) for ct in ds]
                if reduce(operator.xor, inv_nibble_ds)!=0:
                    break
            else:
                lrk_guess[ki,kj] = kv 
                break

lrk_guess = from_matrix_dict(lrk_guess)
print(lrk_guess.hex())
```

### Reversing the key schedule

Once we recovered the last-round key, we must invert the key schedule in some way to recover the master key.

A possible approach is to treat this as a satisfiability problem. The result provides 2 possible solutions. It will be then easy to verify which of them is the right one.

```py
from z3 import Solver, BitVec, LShR, sat

def rotr(val, r, size):
    return LShR(val, r) | ((val & (1<<r)-1) << (8*size-r))

s = Solver()
key = BitVec('key', 128)
recovered = int.from_bytes(lrk_guess, byteorder='big')
s.add(rotr(key, 63, 16) ^ LShR(key, 1) == recovered)
solutions = list()
while s.check() == sat:
    m = s.model()
    k = m[key].as_long()
    solutions.append(int.to_bytes(k, length=16, byteorder='big'))
    s.add(key != k)

print([k.hex() for k in solutions])
```

### Full exploit

{{< details summary="Full Exploit Code" open=false class="big-detail">}}

#### solve.py

```py
from spaes import *
import operator
from functools import reduce
from pwn import remote, log
from z3 import Solver, BitVec, LShR, sat
from base64 import b64encode, b64decode
import re
import os

HOST = os.environ.get("HOST", "spaes-1.challenges.ctrl-space.gg")
PORT = int(os.environ.get("PORT", 10019))
DS_NUMBER = 5

def shift_row_pos(i,j):
    return (i,j-i if j>=i else j+8-i)

def xor_bytes(a, b):
    return bytes(i^j for i, j in zip(a, b))

def set_nibble(s,i,j,v):
    m = to_matrix(s)
    m[i][j] = v
    return from_matrix(m)

def null_nibbles(s):
    m = to_matrix(s)
    return set([(i,j) for j in range(8) for i in range(4) if m[i][j]==0])

def enc_r(m, k, t, rounds):

    RCON = [bytes.fromhex(x) for x in CONSTS]
    
    state = to_matrix(m)
    key_matrix = to_matrix(k)
    tweak_matrix = to_matrix(t)

    state = [[state[i][j] ^ key_matrix[i][j] for j in range(8)] for i in range(4)]

    for r in range(rounds):
        state = [[SBOX[state[i][j]] for j in range(8)] for i in range(4)]
        state = shift_rows(state)
        state = mix_columns(state)
        round_const_matrix = to_matrix(RCON[r])
        state = [[state[i][j] ^ round_const_matrix[i][j] for j in range(8)] for i in range(4)]

        if r % 2 == 0:
            state = [[state[i][j] ^ key_matrix[i][j] for j in range(8)] for i in range(4)]
        else:
            state = [[state[i][j] ^ tweak_matrix[i][j] for j in range(8)] for i in range(4)]

    c = from_matrix(state)
    return c

def remote_enc(r, pt):
    r.recvuntil(b"choice:")
    r.sendline(b"1")
    r.recvuntil(b":")
    r.sendline(b64encode(pt))
    ct = b64decode(r.recvline())
    return ct

def inv_round_nibble(n,kv):
    s = n ^ kv
    s = inv_sbox[s]
    return s

def get_deltasets(r, mappings):
    log.info("Getting deltasets...")
    deltasets = dict()
    plaintext = b""
    for i,j in mappings:
        for _ in range(DS_NUMBER):
            pt_const = os.urandom(16)
            for v in range(16):
                plaintext += set_nibble(pt_const,i,j,v)

    ciphertext = remote_enc(r, plaintext)
    for i,j in mappings:
        deltasets[i,j] = list()
        for dsn in range(DS_NUMBER):
            deltasets[i,j].append(list())
            for _ in range(16):
                deltasets[i,j][dsn].append(ciphertext[0:16])
                ciphertext = ciphertext[16:]

    return deltasets

def get_secret_file(r):
    log.info("Getting secret file...")
    r.recvuntil(b"choice:")
    r.sendline(b"2")
    return b64decode(r.readline())

def from_matrix_dict(state):
    return bytes([state[i,j] << 4 | state[(i+1),j] for j in range(8) for i in (0, 2)])

def extract_master_key(lrk_guess):
    def rotr(val, r, size):
        return LShR(val, r) | ((val & (1<<r)-1) << (8*size-r))

    s = Solver()
    key = BitVec('key', 128)
    recovered = int.from_bytes(lrk_guess, byteorder='big')
    s.add(rotr(key, 63, 16) ^ LShR(key, 1) == recovered)
    solutions = list()
    while s.check() == sat:
        m = s.model()
        k = m[key].as_long()
        solutions.append(int.to_bytes(k, length=16, byteorder='big'))
        s.add(key != k)
    return solutions

def get_mappings():
    log.info("Getting mappings...")
    key = os.urandom(16)
    tweak = b"\x00"*16
    mappings = dict()
    mappings = {(i,j):dict() for i in range(4) for j in range(8)}
    for i,j in mappings:
        ds_sums = list()
        for _ in range(DS_NUMBER):
            acc = b"\x00"*16
            pt_const = os.urandom(16)
            for val in range(16):
                pt = set_nibble(pt_const,i,j,val)
                ct = enc_r(pt, key, tweak, 5)
                acc = xor_bytes(acc, ct)
            ds_sums.append(acc)
        mapping = set.intersection(*list(map(null_nibbles, ds_sums)))
        mapping = set(map(lambda c: shift_row_pos(c[0],c[1]), mapping))
        mappings[i,j] = mapping
    mappings[0,0].remove((0,5)) # we saw this mapping generates false positives
    return mappings

def extract_last_round_key(mappings, deltasets):
    lrk_guess = {(i,j):None for i,j in mappings}
    for i,j in mappings:
        for ki,kj in mappings[i,j]:
            if lrk_guess[ki,kj] is not None:
                continue
            for kv in range(16):
                for dsn in range(DS_NUMBER):
                    ds = deltasets[i,j][dsn]
                    inv_nibble_ds = [inv_round_nibble(to_matrix(ct)[ki][kj],kv) for ct in ds]
                    if reduce(operator.xor, inv_nibble_ds)!=0:
                        break
                else:
                    lrk_guess[ki,kj] = kv 
                    break
    return from_matrix_dict(lrk_guess)

def extract_flag(secret_file, guessed_master_keys):
    for gmk in guessed_master_keys:
        try:
            c = spAES(gmk)
            pt = c.decrypt_ecb(secret_file).decode()
            match = re.search("space{.+}", pt)
            if match:
                return match.group(0)
        except:
            pass

def pwn():
    mappings = get_mappings()
    r = remote(HOST, PORT)
    secret_file = get_secret_file(r)
    deltasets = get_deltasets(r, mappings)
    r.close()

    lrk_guess = extract_last_round_key(mappings, deltasets)
    log.info(f"Last round key guess: {lrk_guess.hex()}")

    master_key_guesses = extract_master_key(lrk_guess)
    log.info(f"Master key candidates: {[k.hex() for k in master_key_guesses]}")

    flag = extract_flag(secret_file, master_key_guesses)
    log.success(f"FLAG: {flag}")

pwn()
```

Additionally, we need the implementation of the cipher that includes the decryption routine, which is provided below.

#### spaes.py

```py
from Crypto.Util.Padding import pad, unpad

###

SBOX = [4, 14, 13, 5, 0, 9, 2, 15, 11, 8, 12, 3, 1, 6, 7, 10]

inv_sbox = [0] * 16
for i, v in enumerate(SBOX):
    inv_sbox[v] = i

ROUNDS = 6

CONSTS = ['6d6ab780eb885a101263a3e2f73520c9', 'f71df57947881932a33a3a0b8732b912', '0aa5df6fadf91c843977d378cc721147', '4a8f29cf09b62619c596465a59fb9827', '29b408cfd4910c80866f5121c6b1cc77', '8589c67a30dbced873b34bd04f40b7cb', '6d64bc8485817ba330fc81b9d2899532', '46495adad2786761ae89e8c26ff1c769', '747470d62b219d12abf9a0816b950639', '4ed2d429061e5d13a2b2ad1df1e63110']

def rotr_128(x, n):
    return ((x >> n) | (x << (128 - n))) & ((1 << 128) - 1)

def rotl_4(x, n):
    return ((x << n) | (x >> (4 - n))) & ((1 << 4) - 1)

def to_matrix(bts):
    return [
        [bts[i] >> 4 for i in range(0, 16, 2)],
        [bts[i] & 0x0F for i in range(0, 16, 2)],
        [bts[i] >> 4 for i in range(1, 16, 2)],
        [bts[i] & 0x0F for i in range(1, 16, 2)],
    ]

def from_matrix(state):
    return bytes([state[i][j] << 4 | state[i + 1][j] for j in range(8) for i in (0, 2)])

def shift_rows(state):
    return [
        state[0],
        state[1][1:] + state[1][:1],
        state[2][2:] + state[2][:2],
        state[3][3:] + state[3][:3]
    ]

def inv_shift_rows(state):
    return [
        state[0],
        state[1][-1:] + state[1][:-1],
        state[2][-2:] + state[2][:-2],
        state[3][-3:] + state[3][:-3],
    ]

def mix_columns(state):
    mixed = [[0 for i in range(8)] for j in range(4)]
    for i in range(8):
        mixed[0][i] = state[1][i] ^ rotl_4(state[2][i], 1) ^ rotl_4(state[3][i], 2)
        mixed[1][i] = state[2][i] ^ rotl_4(state[3][i], 1) ^ rotl_4(state[0][i], 2)
        mixed[2][i] = state[3][i] ^ rotl_4(state[0][i], 1) ^ rotl_4(state[1][i], 2)
        mixed[3][i] = state[0][i] ^ rotl_4(state[1][i], 1) ^ rotl_4(state[2][i], 2)
    return mixed

def inv_mix_columns(state):
    unmixed = [[0 for i in range(8)] for j in range(4)]
    for i in range(8):
        unmixed[0][i] = state[3][i] ^ rotl_4(state[1][i], 2) ^ rotl_4(state[2][i], 3)
        unmixed[1][i] = state[0][i] ^ rotl_4(state[2][i], 2) ^ rotl_4(state[3][i], 3)
        unmixed[2][i] = state[1][i] ^ rotl_4(state[3][i], 2) ^ rotl_4(state[0][i], 3)
        unmixed[3][i] = state[2][i] ^ rotl_4(state[0][i], 2) ^ rotl_4(state[1][i], 3)
    return unmixed

def enc(m, k, t):
    assert len(m) == 16
    assert len(k) == 16
    assert len(t) == 16

    RCON = [bytes.fromhex(x) for x in CONSTS]

    final_key = int.from_bytes(k, byteorder='big')
    final_key = rotr_128(final_key, 63) ^ (final_key >> 1)
    final_key = int.to_bytes(final_key, length=16, byteorder='big')
    
    state = to_matrix(m)
    key_matrix = to_matrix(k)
    tweak_matrix = to_matrix(t)
    final_key_matrix = to_matrix(final_key)

    state = [[state[i][j] ^ key_matrix[i][j] for j in range(8)] for i in range(4)]

    for r in range(ROUNDS-1):
        state = [[SBOX[state[i][j]] for j in range(8)] for i in range(4)]
        state = shift_rows(state)
        state = mix_columns(state)
        round_const_matrix = to_matrix(RCON[r])
        state = [[state[i][j] ^ round_const_matrix[i][j] for j in range(8)] for i in range(4)]

        if r % 2 == 0:
            state = [[state[i][j] ^ key_matrix[i][j] for j in range(8)] for i in range(4)]
        else:
            state = [[state[i][j] ^ tweak_matrix[i][j] for j in range(8)] for i in range(4)]

    state = [[SBOX[state[i][j]] for j in range(8)] for i in range(4)]
    state = shift_rows(state)
    state = [[state[i][j] ^ final_key_matrix[i][j] for j in range(8)] for i in range(4)]

    c = from_matrix(state)
    return c

def dec(c, k, t):
    assert len(c) == 16
    assert len(k) == 16
    assert len(t) == 16

    RCON = [bytes.fromhex(x) for x in CONSTS]

    final_key = int.from_bytes(k, byteorder='big')
    final_key = rotr_128(final_key, 63) ^ (final_key >> 1)
    final_key = int.to_bytes(final_key, length=16, byteorder='big')

    key_matrix = to_matrix(k)
    tweak_matrix = to_matrix(t)
    final_key_matrix = to_matrix(final_key)
    state = to_matrix(c)

    state = [[state[i][j] ^ final_key_matrix[i][j] for j in range(8)] for i in range(4)]
    state = inv_shift_rows(state)
    state = [[inv_sbox[state[i][j]] for j in range(8)] for i in range(4)]

    for r in range(ROUNDS - 2, -1, -1):
        if r % 2 == 0:
            state = [[state[i][j] ^ key_matrix[i][j] for j in range(8)] for i in range(4)]
        else:
            state = [[state[i][j] ^ tweak_matrix[i][j] for j in range(8)] for i in range(4)]

        round_const_matrix = to_matrix(RCON[r])
        state = [[state[i][j] ^ round_const_matrix[i][j] for j in range(8)] for i in range(4)]
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = [[inv_sbox[state[i][j]] for j in range(8)] for i in range(4)]

    state = [[state[i][j] ^ key_matrix[i][j] for j in range(8)] for i in range(4)]
    return from_matrix(state)

###

class spAES:
    def __init__(self, master_key):
        self.master_key = master_key
        self.tweak = b"\x00"*16

    def encrypt_ecb(self, plaintext):
        plaintext = pad(plaintext, 16)
        blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
        return b"".join([enc(block, self.master_key, self.tweak) for block in blocks])

    def decrypt_ecb(self, chipertext):
        blocks = [chipertext[i:i+16] for i in range(0, len(chipertext), 16)]
        return unpad(b"".join([dec(block, self.master_key, self.tweak) for block in blocks]), 16)
```

{{</details>}}



Below the execution.

```
$ python3 solve.py
[*] Getting mappings...
[+] Opening connection to spaes-1.challenges.ctrl-space.gg on port 10019: Done
[*] Getting secret file...
[*] Getting deltasets...
[*] Closed connection to spaes-1.challenges.ctrl-space.gg port 10019
[*] Last round key guess: 86c1b5ec60eef8bf9926bdd994bd4712
[*] Master key candidates: ['951ac41042652e7966266bf220ee37c1', '3fb06ebae8cf84d3cc8cc1588a449d6b']
[+] FLAG: space{M4yb3_s1x_r0und5_Ar3_n0t_en0ugh?!}
```