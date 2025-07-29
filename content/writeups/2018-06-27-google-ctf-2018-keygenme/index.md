---
title: "KEYGENME - Google CTF 2018"
date: "2018-06-27"
description: "Write-up for the KEYGENME challenge from Google CTF 2018."
tags: ["google", "ctf", "reversing", "mhackeroni"]
showAuthor: false
---

{{< lead >}}
Authors: marcof, nearffxx, Mercurio
{{< /lead >}}

> *I bet you can't reverse this algorithm!*  
$ nc keygenme.ctfcompetition.com 1337

This was a 249pts reversing challenge from GoogleCTF-2018 


Stage One
----

We are given an ELF 64 binary with an encrypted section containing its code base. The code is xored at runtime with an hardcoded key and later executed. We wrote an IDC script to decript the binary and make it possible to analyze in IDA.

```c 
#include <idc.idc>

static decrypt(from, size, key ) { 
  auto i, x;            
  for ( i=0; i < size; i=i+1 ) { 
    x = get_qword(from);   // fetch the byte
    x = (x^key);           // decrypt it
    patch_qword(from,x);   // put it back
    from = from + 8;       // next byte
  } 
}

static stage_1() { 
  decrypt(0x6001bc, 0x44a8, 0x1122334455667788);
  patch_byte(0x4000da,0x56); // we push rsi (containing the decrypted code address)
  patch_byte(0x4000db,0xc3); // retn
}
```

Now we learned the program is forking and ptracing its child process right after. The child process instead calls execve on "/proc/self/fd/3" which contains the main keygen logic. Our way to dump the child binary was to break before the execve and copy the binary using cp. For sake of simplicity we called this *main3*

```bash
(gdb) set follow-fork-mode child
(gdb) catch syscall execve
Catchpoint 1 (syscall 'execve' [59])
(gdb) r
Starting program: /home/nearffxx/tmp/main
[New process 24430]


[Switching to process 24430]

Thread 2.1 "main_o" hit Catchpoint 1 (call to syscall execve), 0x00007ffff7fddc10 in ?? 
(gdb) !cp /proc/24430/fd/3 main3
```

Understanding main3 (child process)
-------
As soon as we opened the child process we noticed antidebugging techniques. Basically the original code was filled with a bunch of trap instructions. The parent process would intercept its child traps and restore the original instructions.

We straced the parent process to observe the patches it was supplying to its child. Below the significant output:

```bash
process_vm_writev(26117, [{iov_base="\x01\xca", iov_len=2}], 1, [{iov_base=0x555555554d56, iov_len=2}], 1, 0) = 2
process_vm_writev(26117, [{iov_base="\x01\xca\x01", iov_len=3}], 1, [{iov_base=0x555555555549, iov_len=3}], 1, 0) = 3
process_vm_writev(26117, [{iov_base="\x01\xd0", iov_len=2}], 1, [{iov_base=0x5555555552b6, iov_len=2}], 1, 0) = 2
process_vm_writev(26117, [{iov_base="\x01\xd0", iov_len=2}], 1, [{iov_base=0x5555555553c5, iov_len=2}], 1, 0) = 2
process_vm_writev(26117, [{iov_base="\x01\xd0\x89", iov_len=3}], 1, [{iov_base=0x555555554f2e, iov_len=3}], 1, 0) = 3
process_vm_writev(26117, [{iov_base="\x31\xd1\x48", iov_len=3}], 1, [{iov_base=0x555555554da8, iov_len=3}], 1, 0) = 3
process_vm_writev(26117, [{iov_base="\x41\x5d", iov_len=2}], 1, [{iov_base=0x555555555c1e, iov_len=2}], 1, 0) = 2
process_vm_writev(26117, [{iov_base="\x48\x83\xc2", iov_len=3}], 1, [{iov_base=0x555555554e3b, iov_len=3}], 1, 0) = 3
process_vm_writev(26117, [{iov_base="\x48\x83\xc2", iov_len=3}], 1, [{iov_base=0x555555555540, iov_len=3}], 1, 0) = 3
process_vm_writev(26117, [{iov_base="\x48\x8b", iov_len=2}], 1, [{iov_base=0x5555555559e9, iov_len=2}], 1, 0) = 2
process_vm_writev(26117, [{iov_base="\x48\x8b", iov_len=2}], 1, [{iov_base=0x555555555aed, iov_len=2}], 1, 0) = 2
process_vm_writev(26117, [{iov_base="\x48\x8b\x85", iov_len=3}], 1, [{iov_base=0x555555554b67, iov_len=3}], 1, 0) = 3
process_vm_writev(26117, [{iov_base="\x48\x8d", iov_len=2}], 1, [{iov_base=0x555555554b71, iov_len=2}], 1, 0) = 2
process_vm_writev(26117, [{iov_base="\x48\xc1", iov_len=2}], 1, [{iov_base=0x555555554845, iov_len=2}], 1, 0) = 2
process_vm_writev(26117, [{iov_base="\x5d\x41", iov_len=2}], 1, [{iov_base=0x555555555c1b, iov_len=2}], 1, 0) = 2
process_vm_writev(26117, [{iov_base="\x5e\x48\x89", iov_len=3}], 1, [{iov_base=0x5555555547c5, iov_len=3}], 1, 0) = 3
process_vm_writev(26117, [{iov_base="\x89\x45\xd8", iov_len=3}], 1, [{iov_base=0x555555554cc8, iov_len=3}], 1, 0) = 3
process_vm_writev(26117, [{iov_base="\x8b\x00", iov_len=2}], 1, [{iov_base=0x5555555558bd, iov_len=2}], 1, 0) = 2
process_vm_writev(26117, [{iov_base="\x8b\x0a", iov_len=2}], 1, [{iov_base=0x555555555186, iov_len=2}], 1, 0) = 2
process_vm_writev(26117, [{iov_base="\x8b\x12\x01", iov_len=3}], 1, [{iov_base=0x555555554d25, iov_len=3}], 1, 0) = 3
process_vm_writev(26117, [{iov_base="\x8b\x45\xbc", iov_len=3}], 1, [{iov_base=0x5555555552f6, iov_len=3}], 1, 0) = 3
process_vm_writev(26117, [{iov_base="\x8b\x45\xc4", iov_len=3}], 1, [{iov_base=0x555555554e22, iov_len=3}], 1, 0) = 3
process_vm_writev(26117, [{iov_base="\x8b\x45\xe0", iov_len=3}], 1, [{iov_base=0x555555554feb, iov_len=3}], 1, 0) = 3
process_vm_writev(26117, [{iov_base="\x8b\x45\xf4", iov_len=3}], 1, [{iov_base=0x555555554934, iov_len=3}], 1, 0) = 3
process_vm_writev(26117, [{iov_base="\x8b\x4d\xc8", iov_len=3}], 1, [{iov_base=0x5555555555f1, iov_len=3}], 1, 0) = 3
process_vm_writev(26117, [{iov_base="\x8b\x55", iov_len=2}], 1, [{iov_base=0x555555554e32, iov_len=2}], 1, 0) = 2
process_vm_writev(26117, [{iov_base="\x8b\x55", iov_len=2}], 1, [{iov_base=0x555555554e61, iov_len=2}], 1, 0) = 2
process_vm_writev(26117, [{iov_base="\x8b\x55\xdc", iov_len=3}], 1, [{iov_base=0x555555555482, iov_len=3}], 1, 0) = 3
process_vm_writev(26117, [{iov_base="\x90\x5d\xc3", iov_len=3}], 1, [{iov_base=0x555555555744, iov_len=3}], 1, 0) = 3
process_vm_writev(26117, [{iov_base="\xc1\xe8\x08", iov_len=3}], 1, [{iov_base=0x555555555b0f, iov_len=3}], 1, 0) = 3
```
We parsed this output using an helper python script to generate IDC valid patching instructions we later copy-pasted in the IDA cmd-line.

```python
import re


f = file("./patches")
patches = f.read().split("\n")[:-2]

for l in patches:
	# print l
	addr = int(l[l.index("iov_base=",45)+9:l.index("iov_base=",45)+9+14],16)-0x555555554000
	patch_len = int(l[l.index("iov_len=")+8:l.index("iov_len=")+8+1])
	patch = l[l.index("iov_base=")+10:l.index("iov_base=")+10+(patch_len*4)]
	patch_s = patch.split("\\")
	for j in xrange(patch_len):
		print "patch_byte("+hex(addr+j)+", 0"+patch_s[j+1] +");"
```
Which gave us:

```
marcof:(~/googlectf/keygenme)$ python patcher.py 
patch_byte(0xd56, 0x01);
patch_byte(0xd57, 0xca);
patch_byte(0x1549, 0x01);
patch_byte(0x154a, 0xca);
patch_byte(0x154b, 0x01);
patch_byte(0x12b6, 0x01);
.
.
```

main3 reversing
----
This binary takes as input a 5byte validation code and a 32byte serial key. The serial key is shuffled according to some algorithm we didn't want to reverse. The scrumbled key is then compared with another value whose generation also we absolutely didn't want to reverse, surely something depending on the 5byte validation code. With a black box apporach we were able to both obtain the xoring key (inputing a "0"x32 serial) and the byte mappings (find them in the final exploit). The only thing we missed now was a way to obtain the comparing value generated from the validation code.


Solution
----
The fastest way for us was to patch out the final strcmp() and substitute it with a puts() in our child binary (main3). For unknown reasons running main3 exlusively was not working so we rapidly produced a patched main version calling execve on it.

```c
// Patch of main binary to execve our patched main3
patch_byte(0x603da2,'m');
patch_byte(0x603da3,'a');
patch_byte(0x603da4,'i');
patch_byte(0x603da5,'n');
patch_byte(0x603da6,'3');
patch_byte(0x603da7,0x00);
```

Our approach now is:
- we get the 5 byte validation code from the server
- we pass it to our patched version of the binary
- the inserted puts() gives us the comparing value 
- we apply the byte mappings and xoring key on this value
- we sent it back to the server
- ~~we get the flag~~
- no actually repeat 100 times
- we get the flag


Final exploit
---

```python
from pwn import *

## this looks stupid but at the time we thought the mapping was far more complex
maps = {0:30,1:1,2:28,3:3,4:26,5:5,6:24,7:7,8:22,9:9,10:20,11:11,12:18,13:13,14:16,15:15,
		16:14,17:17,18:12,19:19,20:10,21:21,22:8,23:23,24:6,25:25,26:4,27:27,28:2,29:29,30:0,31:31}

key = 0x00112233445566778899aabbccddeeff

def map_key(otp):

    arr = ["a"] * 32
    b = key^otp
    b = hex(b)[2:].rjust(32,'0')
    for i,c in enumerate(b):
        # print i,c
        arr[maps[i]] = c
    # print "UNAMPPED: " + b

    return "".join(arr)

r = remote('keygenme.ctfcompetition.com',1337)

count = 0
while True:
    num = r.recvuntil('\n')[:-1]
    if('CTF{' in num):
        print "FLAG?: " + num
        print "COUNT: " + str(count)
        break
    count += 1
    p = process('./main')
    p.sendline(num+"0"*32)
    xored = p.recvuntil('\n')[:-1]
    p.close()
    # print "CODE:     " + num
    # print "XORED:    " + xored
    result = map_key(int(xored,16))
    # print "MAPPED:   " + result
    r.sendline(result)
    r.recvuntil("OK\n")
```

Attachments
----
The original challenge files [here](https://drive.google.com/file/d/1CP7QQSWPNgzo_Hgxd78PyBi0WWReWMbC/view?usp=sharing)  
Final exploit, patched *main* and *main3* binaries [here](https://drive.google.com/file/d/1VAU2HdpnfJOLSuxX3lsM3kQaTVhcZWPx/view?usp=sharing)