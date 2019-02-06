---
title: "Butterfree - Codegate Quals 2019"
author: "chq-matteo"
comments: true
tags: codegate ctf unintended mhackeroni
---

> How not to pwn a modified 2018.11.18 Webkit

```
Butterfree
Download 2018.11.18 Webkit and Modified 

nc 110.10.147.110 17423 
Download 
Download2
```

We are given access to a JavaScriptCore shell.  
There was an hint on the official discord of the ctf that there was an unintended solution to this challenge, specifically a one-liner.

Given the hint we tried to `require` some path where the flag could be at.

Executing `require('flag')` we get a syntax error related to '{'.

We found that there is a debug feature in jsc shell that allows read from the file system

https://bugs.webkit.org/show_bug.cgi?id=125059

In the end the solution to the challenge is

```
> console.log(readFile('flag'))
flag{4240a8444fe8734044fca90700b3ade2}
```


The intended solution is very similar to https://github.com/WebKit/webkit/commit/650552a6ed7cac8aed3f53dd464341728984b82f
