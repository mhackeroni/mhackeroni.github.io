---
title: "DOGESTORE - Google CTF 2018"
date: "2018-06-30"
description: "Write-up for the DOGESTORE challenge from Google CTF 2018."
tags: ["google", "ctf", "crypto", "mhackeroni"]
showAuthor: false
---

{{< lead >}}
Authors: pietroferretti, chqmatteo
{{< /lead >}}

>Secret Cloud Storage System: This is a new system to store your end-to-end encrypted secrets. Now with SHA3 integrity checks!
>$ nc dogestore.ctfcompetition.com 1337


Attached we find:

 - [`fragment.rs`](/handouts/dogestore/fragment.rs), some partial Rust source code for the challenge;
 - [`encrypted_secret`](/handouts/dogestore/encrypted_secret), a 110 bytes large binary file.


## Understanding the challenge

Let's start by taking a look at the Rust source code we were provided.

```rust
const FLAG_SIZE: usize = 56;
const FLAG_DATA_SIZE: usize = FLAG_SIZE * 2;

#[derive(Debug, Copy, Clone)]
struct Unit {
    letter: u8,
    size: u8,
}

fn deserialize(data: &Vec<u8>) -> Vec<Unit> {
    let mut secret = Vec::new();
    for (letter, size) in data.iter().tuples() {
        secret.push(Unit {
            letter: *letter,
            size: *size,
        });
    }
    secret
}

fn decode(data: &Vec<Unit>) -> Vec<u8> {
    let mut res = Vec::new();
    for &Unit { letter, size } in data.iter() {
        res.extend(vec![letter; size as usize + 1].iter())
    }
    res
}

fn decrypt(data: &Vec<u8>) -> Vec<u8> {
    key = get_key();
    iv = get_iv();
    openssl::symm::decrypt(
        openssl::symm::Cipher::aes_256_ctr(),
        &key,
        Some(&iv),
        data
    ).unwrap()
}

fn store(data: &Vec<u8>) -> String {
    assert!(
        data.len() == FLAG_DATA_SIZE,
        "Wrong data size ({} vs {})",
        data.len(),
        FLAG_DATA_SIZE
    );
    let decrypted = decrypt(data);
    let secret = deserialize(&decrypted);
    let expanded = decode(&secret);
    base64::encode(&compute_sha3(&expanded)[..])
}
```

As suggested by the name (`fragment.rs`), the source code is partial, but we can nonetheless understand what it's supposed to do.

`store` is the function that calls all the other functions, and works like this:
 - read 56*2 = 112 bytes,
 - "decrypt" the data,
 - "deserialize" the data,
 - "decode" the data,
 - return the SHA-3 hash of the result, encoded in base64.


We try to interact with the service at `dogestore.ctfcompetition.com` to check if it works in a similar way.

The service reads exactly 110 bytes, and returns a base64-encoded string, which decodes to 32 bytes.

The service's behaviour seems to match the source code, except for reading 110 bytes instead of 112. Close enough to be FLAG_SIZE*2, but we guess the organizers messed something up and FLAG_SIZE is actually 55. Among the SHA-3 variants, 32 bytes means SHA-3-256 is probably the one used by the service.

The challenge emulates a service taking some encrypted, serialized data, restoring it back to original, and returning a checksum.

Let's dive more deeply in each function.

### Decryption
This function decrypts the 110 bytes using AES-CTR (AES counter mode). We assume the IV and the key are fixed, since we can't supply them and the service is supposed to be deterministic.

### Deserialization
This function parses and deserializes the decrypted data.

`tuples()` is not defined, but we assume (looking at the Unit struct) that it iterates through the byte vector 2 bytes at a time. For each pair, the first byte is read as a "letter", the second as a "size".

### Decoding
The deserialized data is then "expanded" back to original size like this: for each letter-size pair, repeat the letter *size*+1 times.

Let's see an example:
```
input: 'A \x00 B \x04 C \x01' (these are contiguous bytes)

A repeated 0+1=1 times
B repeated 4+1=5 times
C repeated 1+1=2 times

output: 'ABBBBBCC'
```

We now know the format of the decrypted data: the data is like
```
1 byte: letter
1 byte: size - 1
... repeated 55 times
total length = 55*2 = 110 bytes

Example: 'A\x00B\x04C\x01w\x00t\x02...'
```

Since usually serialization tries to save as much space as possible, we expect each letter to be different from the previous one.

### Approach
`encrypted_secret` is 110 bytes long, same size as the service input. Looking at the filename, this is probably the serialized, encrypted flag.

Let's start by submitting the secret to the service.
The service sends back the SHA-3 hash of the decrypted secret:

`ff1e690dea4fa3384cfb151e95abe92fde33e57d69d8c1f97107d0bbccf8a1d6`

We can't do much with this, but it could be useful for some additional final checks.

To move to the actual attack, some crypto basics are needed.
Skip the next section if this stuff is old news for you.

## Crypto Background

### SHA-3
SHA-3 is a cryptographic hashing function, i.e. a function that maps a message of arbitrary length to a fixed-size digest.

One of the main properties of a cryptographic hash function is that it is *non-invertible*: we can't recover the original message from a digest.
We'll have to find another way to find the secret.

### AES-CTR

AES is a block cipher, but it can work in many different *modes of operation*.

AES-CTR specifically is a mode of operation which makes AES work like a *stream* cipher. Instead of encrypting a message block by block, we generate a continuous, unpredictable bitstream. The bitstream (also called keystream) is  simply XOR-ed with the plaintext to generate the ciphertext.

![AES-CTR](/img/dogestore_writeup/ctr-encryption.png)

The keystream depends on both the IV (initialization vector, or nonce) and the key. In this challenge we assume the IV and the key are fixed, since we can't provide them and we expect the service to be deterministic.

This means that in this specific case the keystream is fixed, and AES-CTR is reduced to a simple XOR cipher.

Let's see an example. Consider as plaintext the string "Wiki" (01010111 01101001 01101011 01101001 in 8-bit ASCII).

Encryption with a XOR cipher and a sample keystream:
```
   01010111 01101001 01101011 01101001  // plaintext
 ⊕ 11110011 01100011 11101001 00110010  // keystream
 = 10100100 00001010 10000010 01011011  // ciphertext
```
Decryption is done by XOR-ing the ciphertext with the keystream again:
```
   10100100 00001010 10000010 01011011  // ciphertext
 ⊕ 11110011 01100011 11101001 00110010  // keystream
 = 01010111 01101001 01101011 01101001  // plaintext
```

#### Attacks on AES-CTR
Without integrity checks, AES-CTR is *malleable*. By manipulating the ciphertext, we can purposefully modify the plaintext it will be decrypted to, even if we don't know the plaintext itself.

This is because, since aes-ctr is equivalent to a simple XOR cipher, when we flip a bit in the ciphertext the bit will be flipped in the plaintext too!

Let's see an example. We take the same ciphertext as the previous example, and flip an arbitrary bit.

`10100100 00001010 10000010 01011011 -> 10100100 00001010 1000001*1* 01011011`

```
   10100100 00001010 10000011 01011011  // modified ciphertext
 ⊕ 11110011 01100011 11101001 00110010  // keystream
 = 01010111 01101001 01101010 01101001  // new plaintext
```
The plaintext bit in the same position was flipped.

`01010111 01101001 01101011 01101001 -> 01010111 01101001 0110101*0* 01101001`

Decrypted plaintext: "Wi**j**i" instead of "Wiki".

Since we know the format of the encrypted data, we can use this trick to our advantage to edit the plaintext in critical positions.

## Finding the letters

Let's think about it. The only output the service is willing to give us is the hash of the decoded plaintext. We can't do much with it, except for checking if the hash is one we already know.
We need to use this hash to guess the content of the plaintext.

We can use the fact that two different serializations can be decoded to the same message: if the same letter appears twice in a row in the serialized data, as long as the sum of the sizes of the two repeated letters is the same, the decoded message will also be the same (and the hash will be too).

Example:
```
'A\x02A\x02' is decoded as 'AAAAAA'
'A\x01A\x03' is also decoded as 'AAAAAA'
```

We will use this and some clever xor tricks to run automated tests on the plaintext values, and leak the content.

The attack:
 - consider a pair of adjacent "letters" (i.e. letter 1 + size 1 + letter 2 + size 2)
 - XOR the second letter with the mask M
 - XOR the least significant bit of the size bytes in all the possible configurations (0 and 0, 0 and 1, 1 and 0, 1 and 1)
     - if the letter are XORed to be the same, two of the four combinations will produce a message where the letter is repeated for the same total number of times, and therefore two hashes will match
     - if the letters are not XORed to be the same, no match will be found
 - try XOR-ing with a different value M until a match is found (up to 256)
 - repeat for each pair of adjacent letters (from 1 to 55)

When a match is found, we will have leaked the value M = letter 1 XOR letter 2.

Example:
```
original plaintext: A\x03D\x05
if the letter is xor-ed correctly, the second letter will be the same as the first in the new plaintext:
...
xor 2 -> A\x03C\x05

xor first size, xor second size -> result
0,0 -> A\x03C\x05 tot 10, decoded as AAAACCCCCC
0,1 -> A\x03C\x04 tot 9,  decoded as AAAACCCCC
1,0 -> A\x02C\x05 tot 9,  decoded as AAACCCCCC
1,1 -> A\x02C\x04 tot 8,  decoded as AAACCCCC
*no match*

xor 3 -> A\x03A\x05

xor first size, xor second size -> result
0,0 -> A\x03A\x05 tot 10, decoded as AAAAAAAAAA
0,1 -> A\x03A\x04 tot 9,  decoded as AAAAAAAAA *match*
1,0 -> A\x02A\x05 tot 9,  decoded as AAAAAAAAA *match*
1,1 -> A\x02A\x04 tot 8,  decoded as AAAAAAAA
```

We can prove that, if the next letter is xor-ed to be the same as the current, at least two of the four hashes will be the same. There is always a combination that makes the size increase or decrease by the same amount.
Size variation for each xor bit combination:


|    | 0,0 | 0,1 | 1,0 | 1,1 |
|----|----|----|----|----|
| 0,0 | +0 | **+1** | **+1** | +2 |
| 0,1 | **+0** | -1 | +1 | **+0** |
| 1,0 | **+0** | +1 | -1 | **+0** |
| 1,1 | +0 | **-1** | **-1** | -2 |

On the y axis, we have the lsb of the size bytes for the first and second letter.
On the x axis, the possible xor combinations.

Using this attack we can find all the bitwise differences between adjacent letters. Since we don't know the value of the first letter, we will have to try all of them and guess which is the one that makes more sense. All the other letters can be found using the first value and the differences.


The exploit:

```python
#!/usr/bin/env python3
from socket import socket
from hashlib import sha3_256 as sha3

def bxor(b1, b2):
    parts = []
    for b1, b2 in zip(b1, b2):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)

def gethash(text):
    # send text
    sock = socket()
    sock.connect((host, port))
    sock.send(text)
    # get base64 encoded hash
    data = sock.recv(1024)
    sock.close()
    return data

host = 'dogestore.ctfcompetition.com'
port = 1337

# load encrypted flag
with open('encrypted_secret', 'rb') as f:
    ctext = f.read()
print('Encrypted:')
print(ctext.hex())
print(len(ctext), 'bytes')

nletters = len(ctext) // 2

differences = []
for i in range(0, nletters - 1):
    print('index:', i)
    for c in range(256):
        print('diff:', c)
        hashes = []
        for x, y in ((0, 0), (0, 1), (1, 0), (1, 1)):
            # a) xor next letter to make it the same as the current one
            # b) xor least significant bit of the sizes to create two messages
            # with varying sizes for the current and following letter,
            # but same total size
            mask = b'\x00\x00' * i + \
                   b'\x00' + (x).to_bytes(1, 'little') + \
                   (c).to_bytes(1, 'little') + (y).to_bytes(1, 'little') + \
                   b'\x00\x00' * (nletters - i - 2)
            assert len(mask) == len(ctext)
            h = gethash(bxor(ctext, mask))
            hashes.append(h)
        # if we found a match among the hashes, the letters were the same, and
        # we guessed the bit difference between this letter and the next one
        if len(set(hashes)) < 4:
            print()
            print('Nice!', c)
            differences.append(c)
            print(differences)
            print()
            break

for c in range(256):
    s = chr(c)
    for x in differences:
        s += chr(ord(s[-1]) ^ x)
    print(c)
    print(s)
```

Among the possible candidates, we notice one that follows the ctf flag format:
```
...
72
HFHFHDHDHDSAaACTF{SADASDSDCTF{L_E_R_OY_JENKINS}ASDCTF{
...
```
Sadly we still don't know how many times each letter is repeated in the actual decoded data.

## Finding the sizes

We can mount an attack similar to the previous, but this time we have the advantage of knowing the value of the letters themselves.

Again, we exploit the case where two different serializations are decoded to the same message.

The attack:
 - consider a pair of adjacent "letters" (i.e. letter 1 + size 1 + letter 2 + size 2)
 - XOR the second letter with the mask M we know to make the letters the same
 - consider a bit position in both "size" bytes (e.g. the first bit)
 - flip the bit in the first size byte, get the resulting hash
 - flip the bit in the second size byte, get the resulting hash
 - if the bits were the same, both messages will have the letter repeated the same amount of times, and therefore the same hashes
 - if the bits were opposite, the letter will appear a different amount of times and the hashes will be different
 - repeat for each bit position in the size bytes (from 1 to 8)
 - repeat for each pair of adjacent letters (from 1 to 55)

With this attack we can recover M' = size 1 XOR size 2, one bit at a time.

Example:
```
original plaintext: A\x03D\x02
xor to make the letters match -> A\x03A\x02

bit 1:
-> A\x02A\x02, tot 6, decoded as AAAAAA
-> A\x03A\x03, tot 8, decoded as AAAAAAAA
*no match*
the bits are different

bit 2:
-> A\x01A\x02, tot 5, decoded as AAAAA
-> A\x03A\x00, tot 5, decoded as AAAAA
*match*
the bits are the same
...
```

The exploit:

```python
#!/usr/bin/env python3
from socket import socket
from hashlib import sha3_256 as sha3

def bxor(b1, b2):
    parts = []
    for b1, b2 in zip(b1, b2):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)

def gethash(text):
    # send text
    sock = socket()
    sock.connect((host, port))
    sock.send(text)
    # get base64 encoded hash
    data = sock.recv(1024)
    sock.close()
    return data

host = 'dogestore.ctfcompetition.com'
port = 1337

differences = [14, 14, 14, 14, 12, 12, 12, 12, 12, 23, 18, 32, 32, 2, 23, 18,
               61, 40, 18, 5, 5, 18, 23, 23, 23, 7, 23, 18, 61, 55, 19, 26, 26,
               13, 13, 16, 22, 6, 21, 15, 11, 5, 2, 7, 29, 46, 60, 18, 23, 7,
               23, 18, 61, 113]

# load encrypted flag
with open('encrypted_secret', 'rb') as f:
    ctext = f.read()
print('Encrypted:')
print(ctext.hex())
print(len(ctext), 'bytes')

nletters = len(ctext) // 2

sizes = []
for i in range(0, nletters - 1):
    print('index:', i)
    b = 0
    for j in range(8):
        print('bit', j)
        # check if this bit in the current size byte is different from the one
        # in the following size byte
        # first mask: make letters the same,
        #             change one bit in the size of the first letter
        mask1 = b'\x00\x00' * i + \
                b'\x00' + (1<<j).to_bytes(1, 'little') + \
                (differences[i]).to_bytes(1, 'little') + b'\x00' + \
                b'\x00\x00' * (nletters - i - 2)
        assert len(mask1) == 110
        h1 = gethash(bxor(ctext, mask1))
        # second mask: make letters the same,
        #              change one bit in the size of the second letter
        mask2 = b'\x00\x00' * i + \
                b'\x00\x00' + \
                (differences[i]).to_bytes(1, 'little') + \
                (1<<j).to_bytes(1, 'little') + \
                b'\x00\x00' * (nletters - i - 2)
        assert len(mask2) == 110
        h2 = gethash(bxor(ctext, mask2))
        # if the bits are the same, the size will be increased by the same
        # amount for both letters
        # -> same hash
        # otherwise  one size will be increased, the other decreased
        # -> different hashes
        if h1 == h2:
            print('same')
        else:
            print('different')
            b += (1 << j)
    print(hex(b))
    sizes.append(b)
    print(sizes)
```

Using this exploit we manage to find the bitwise differences between the sizes of each letter.

Again, we don't know the first value, but we guess the one with the smallest values is the most probable.

## Flag
{% raw %}
With the leaked letters and sizes, we can recover the decoded secret, which is `'HFHFHHHDHDHDDDDDDSSSSSSSAAAAaAAAAAACTF{{{SADASDSDCTF{LLLLLLLLL___EEEEE____RRRRRRRRRRR_OYYYYYYYYYY_JEEEEEEENKKKINNSSS}ASDDDDDDDCTF{{{{{\n'`.
{% endraw %}

The sha3 hash of the secret we found is `ff1e690dea4fa3384cfb151e95abe92fde33e57d69d8c1f97107d0bbccf8a1d6`, which matches with the one provided by the server! We're all set.

The flag is the portion following this ctf's flag format, i.e. `CTF{LLLLLLLLL___EEEEE____RRRRRRRRRRR_OYYYYYYYYYY_JEEEEEEENKKKINNSSS}`.

## Additional notes
This challenge was fun, as there were many different way to leak the plaintext content.

For instance, an alternative way to leak the sizes came to our mind after the ctf was finished.

Once we knew the letters, we could just XOR all letters to the same one and get the resulting hash. We could then locally compute the hash of that letter repeated for all possible lengths, and look for a match to find the sum of all the sizes.

The single values could next be found by xoring a letter at a time, and again bruteforcing locally all possible combination of the repetitions of that letter, concatenated with the repetitions of the other letter.

This could have saved some requests to the challenge service, which was often slow while the ctf was running (probably due to high load).
