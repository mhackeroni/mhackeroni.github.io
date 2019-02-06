---
title: "algo_auth - Codegate Quals 2019"
author: "chq-matteo"
comments: true
tags: codegate ctf programming mhackeroni
---

> I like an algorithm

```
nc 110.10.147.104 15712
nc 110.10.147.109 15712
```

```
==> Hi, I like an algorithm. So, i make a new authentication system.
==> It has a total of 100 stages.
==> Each stage gives a 7 by 7 matrix below sample.
==> Find the smallest path sum in matrix, 
    by starting in any cell in the left column and finishing in any cell in the right column, 
    and only moving up, down, and right.
==> The answer for the sample matrix is 12.
==> If you clear the entire stage, you will be able to authenticate.

[sample]
99 99 99 99 99 99 99 
99 99 99 99 99 99 99 
99 99 99 99 99 99 99 
99 99 99 99 99 99 99 
99  1  1  1 99  1  1 
 1  1 99  1 99  1 99 
99 99 99  1  1  1 99 

If you want to start, type the G key within 10 seconds....>> 

```

This challenge is a variant of dijkstra algorithm for shortest path with positive weights

We just need to add a virtual start and end node with zero weight and linked with the leftmost and rightmost cells.

```python
import pwn
import queue
def inside(m, x, y):
    return 0 <= x < len(m) and 0 <= y < len(m[x])

def get_next(m, x, y):
    for i in [-1, 0, 1]:
        for j in [0, 1]:
            if abs(i) + abs(j) == 1 and inside(m, x + i, y + j):
                yield (x + i, y + j)
def shortest_path(m):
    pq = queue.PriorityQueue()
    ssp = dict()
    ssp['ans'] = 10**128
    for i in range(7):
        for j in range(7):
            ssp[(i, j)] = 10**128
        pq.put((m[i][0], [m[i][0]], (i, 0)))
        ssp[(i, 0)] = m[i][0]
    while not pq.empty():
        top, p, coor = pq.get(pq)
        x, y = coor
        if y == len(m[x]) - 1:
            if top < ssp['ans']:
                print(p)
            ssp['ans'] = min(ssp['ans'], top)
        for xi, yi in get_next(m, x, y):
            if top + m[xi][yi] < ssp[(xi, yi)]:
                ssp[(xi, yi)] = top + m[xi][yi]
                pq.put((top + m[xi][yi], p + [m[xi][yi]], (xi, yi)))
    # print(ssp)
    return ssp['ans']
flag = ''
def solve_stage(r):
    global flag
    r.recvuntil('***')
    r.recvline()
    m = []
    for i in range(7):
        m.append(list(map(int, r.recvline().split())))
    l = shortest_path(m)
    flag += chr(l)
    r.sendline(str(l))

def main():
    #pwn.context.log_level = 'DEBUG'
    with pwn.remote('110.10.147.104', 15712) as r:
        r.recvuntil('type the G')
        r.sendline('G')

        for i in range(100):
            solve_stage(r)
        print(flag)
if __name__ == '__main__':
    main()
```

After solving 100 puzzles we don't find the flag, rather we are told that the flag is the solution of the various puzzles

We just added some code to convert the distance to ascii and append it to the flag

It is a base64 that decodes to 

```
FLAG : g00ooOOd_j0B!!!___uncomfort4ble__s3curity__is__n0t__4__security!!!!!
```
