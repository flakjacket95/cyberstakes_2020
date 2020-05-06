# Assembly Voyageur (Miscellaneous 400)
TODO: Provide challenge information once site is back up in training mode.
# Analysis
From reading, this challenge was relatively straightforward on what we needed to do. However, it was a little more difficult to figure out how to do it.

This challenge was about assembling and running code for 5 different architectures. We were given input to provide to the six registers on x86, and the resulting values for each would input values to the next.

As an additional complexity, the webpage kept track of what _trip_ you were on. For each trip, the input values and the code would change around, making it crucial to ensure the challenge was completed before reloading the page, and, ensuring it was right on the first try!

# Approach
I initially wanted to automate this entire process using an emulation system called unicorn. This tool looked perfect for the job here, however, I quickly ran into issues running the given programs in this tool. At that point, I simply gave up and decided to use a more traditional approach.

## Assembling & Linking
Before I can run anything, I have to assemble the programs. The hints so nicely gave me a list of all of the packages needed, but, I didn't really now how to use them! After some research, I learned I could access the underpinnings of `gcc` by using the following format `<arch>-linux-gnu-<type>`. I used this for all except for x86, for which I could simply assembly with `nasm`, with which I was more familiar.

### x86
To compile this x86 code with `nasm`, I needed to add a basic header to the code so that `nasm` was happy.
```nasm
[SECTION .text]
global _start
_start:
  dec eax
  test edx, eax
  setne al
  test ebx, edx
  setz bl
  and edi, 0x1f1f
  bextr esi, ebx, edi
  and esi, 0x1f
  shrx edx, ecx, esi
  sub ecx, edi
  shl esi, 4
  test edi, ecx
  setne al
  shr ebx, 2
  bswap esi
  lea eax, [ebx+2*esi-1773]
  ror ebx, 8
  lea ecx, [esi+4*eax+2372]
  lea esi, [edx+1757]
  and edi, 0x1f
  shlx esi, edx, edi
  not esi
  xchg esi, edi
  test edx, eax
  setz bl
  neg edx
  shl edi, 15
```

Finally, I can assemble this with `nasm -f elf x86.asm -o x86.o`. And I can then link it simply using `ld`, like this, `ld -m elf_i386 -o x86 x86.o`. This program is now a binary that I can run, although it won't just run like usual.

### x86_64
This was a similar process to the x86 one, I could simply add a quick header, and compile using `nasm`.
```nasm
section .text
global _start

_start:
  xor rdi, rdx
  lea rsi, [rdi+1954]
  and rdi, 0x1f1f
  bextr rcx, rdx, rdi
  add rsi, rcx
  mul rdx
  cmpxchg rdi, rbx
  test rcx, rbx
  setz bl
  test rdx, rcx
  jnz label_oeovpcgwsc
  mov rax, rcx
  label_oeovpcgwsc:
  cmpxchg rsi, rax
  and rbx, 0x1f
  shrx rax, rdx, rbx
  test rdi, rbx
  cmovz rcx, rbx
  xchg rdi, rdx
  shl rax, 11
  test rcx, rdx
  setz bl
  lea rax, [rbx+4*rdi+1598]
  and rcx, 0x1f
  shlx rdx, rbx, rcx
  lea rbx, [rdi+2276]
  and rax, 0x1f
  sarx rdi, rdx, rax
  test rdx, rdi
  cmovz rsi, rdi
  test rdi, rcx
  setne al
  sar rdi, 13
  sub rcx, rax
  not rbx
  and rcx, 0x1f
  shlx rbx, rdi, rcx
  sar rdi, 2
  lea rbx, [rax+4*rdx+2343]
  test rsi, rbx
  cmovne rax, rsi
  neg rax
  test rax, rdx
  setne al
  and rdi, 0x1f
  shlx rax, rbx, rdi
  and rdx, 0x1f
  shlx rax, rdi, rdx
  andn rdi, rsi, rcx
```
We can assemble and link this with the following commands: `nasm -f elf64 x86_64.asm` and `ld -o x86_64 x86_64.o`.

### AArch64
This arch is also relatively simple to sort out, I'm also generally familiar with ARM code. I could use the `aarch64-linux-gnu-*` set of programs to assemble and link this program. Again, I had to modify the provided program to add a simple header, and then it would compile as expected.
```nasm
.text
	_start:
 		.global main
 		b main
main:
eon x5, x4, x2
mov x6, x3, LSR #13
mul x4, x2, x1
eon x6, x3, x1, ASR 10
mvn x4, x1
cbnz x3, label_gmbzvvcbrf
mov x6, x2
label_gmbzvvcbrf:
sub x1, x5, x2, LSR #4
sub x2, x5, x3, ASR #8
eor x1, x4, x2
neg x1, x5
sub x2, x4, x1, ASR #10
eon x2, x1, x3, ASR 1
clz x2, x5
cmp x3, x6
sub x4, x6, 2299
add x6, x6, 3819
csel x3, x6, x4, EQ
rev x5, x4
rev32 x5, x3
mvn x6, x5
rev x1, x5
cbnz x1, label_bxupazzakj
mov x5, x3
label_bxupazzakj:
eon x4, x5, x6
```
I also added a simple jump to this to assist in GDB when I was testing it.

I used the assembler command `aarch64-linux-gnu-as -o arm.o arm.asm` and then the link command `aarch64-linux-gnu-gcc -static -oarm arm.o` to setup this binary.

### MIPS
MIPS gave me a bit of trouble initially, as, I could not figure out a way to get it to compile with what are usually referenced as `naked` registers, that is, register names that do not have the preceding `$`. After spending way too much time looking for an easy flag, I simply just went through and edited each register to add the `$`. I also added the same general header as on other aarch64, except, the GNU assembler behaves a bit differently on MIPS, so, it needed `__start` instead of `_start`.
```nasm
.global __start
.text
__start:
	.global main
	b main

main:
  bne $s4, $s2, label_oqkiijzkal
  move $s2, $s1
  label_oqkiijzkal:
  addiu $s4, 2226
  addiu $s3, 3275
  beqz $s1, label_fgyugvquyg
  move $s5, $s3
  label_fgyugvquyg:
  addiu $s5, 3739
  bne $s2, $s4, label_gtnitradyl
  move $s4, $s1
  label_gtnitradyl:
  nor $s2, $s4
  addiu $s6, 716
  xor $s1, $s3
  beq $s1, $s2, label_kdqnqsakcf
  move $s2, $s4
  label_kdqnqsakcf:
  subu $s4, $s3
  addu $s1, $s2
  andi $s2, $s5, 523
  subu $s2, $s4
  xori $s3, $s1, 1147
  bne $s2, 3426, label_opfezurgkz
  move $s1, $s6
  label_opfezurgkz:
  ori $s5, $s3, 1291
  bne $s2, 3705, label_okheiqgeeq
  move $s5, $s6
  label_okheiqgeeq:
  addiu $s6, 2564
  beq $s4, $s6, label_jfillicrnv
  move $s6, $s5
  label_jfillicrnv:
  addiu $s5, 1453
  andi $s4, $s2, 3785
  ori $s1, $s2, 2663
  beq $s2, $s6, label_jbowfdalrg
  move $s6, $s5
  label_jbowfdalrg:
  bne $s1, $s5, label_tyokxumhkl
  move $s5, $s6
  label_tyokxumhkl:
  addiu $s5, 2457
  mult $s5, $s6
  mflo $s5
  mfhi $s4
  nor $s4, $s2
```
Then I can assemble and link with `mips-linux-gnu-as mips.asm -o mips.o` and `mips-linux-gnu-ld -static -o mips mips.o`.
### Power PC
Power PC is the odd ball in this group, I've at least used or seen each of the other languages at some point. However, I had never looked at PPC before. Luckily, the GNU tools worked well again for this one! As usual, I added the general prefix to the code and assembler.
```nasm
.global _start
.text
	_start:
 		.global main
 		b main
main:
  nor r6, r2, r4
  rlwinm r5, r6, 1, 12, 7
  neg r1, r2
  or r5, r6, r3
  cmpwi 7, r6, 793
  bne 7, label_zjsyktmgah
  mr r5, r3
  label_zjsyktmgah:
  eqv r4, r6, r1
  cmpw 7, r2, r4
  beq 7, label_mdvfpguoqt
  mr r4, r6
  label_mdvfpguoqt:
  addi r1, r3, 2880
  subf r4, r1, r2
  xori r4, r2, 798
  cmpw 7, r3, r1
  bne 7, label_fhbrpxmrvw
  mr r1, r2
  label_fhbrpxmrvw:
  cmpw 7, r4, r2
  bne 7, label_xqntolephy
  mr r2, r6
  label_xqntolephy:
  rlwnm r2, r3, r1, 6, 7
  orc r3, r6, r5
  nand r4, r1, r3
  srawi r6, r5, 11
  rlwinm r4, r6, 12, 8, 1
  xor r4, r2, r6
  mulli r1, r2, 1981
  addis r2, r1, 2747
  cmpwi 7, r1, 537
  beq 7, label_anirdpxuei
  mr r5, r4
  label_anirdpxuei:
  cmpw 7, r3, r1
  bne 7, label_gwsfsbbvyf
  mr r1, r4
  label_gwsfsbbvyf:
  addi r2, r5, 3114
  rlwnm r5, r1, r6, 9, 8
  orc r6, r1, r2
  rlwinm r6, r2, 6, 2, 2
  cmpw 7, r6, r2
  bne 7, label_ihtgmbscup
  mr r2, r5
  label_ihtgmbscup:
  cmpw 7, r2, r4
  bne 7, label_qhifwskckq
  mr r4, r6
  label_qhifwskckq:
```
Assembling and linking with `powerpc-linux-gnu-as -mregnames -o ppc.o ppc.asm` and `powerpc-linux-gnu-ld -static -oppc ppc.o`. I had to add the `-mregnames` when I noticed that the provided code did not compile normally originally, and resulted in these errors:
```
ppc.asm: Assembler messages:
ppc.asm:7: Error: unsupported relocation against r6
ppc.asm:7: Error: unsupported relocation against r2
ppc.asm:7: Error: unsupported relocation against r4
ppc.asm:8: Error: unsupported relocation against r5
ppc.asm:8: Error: unsupported relocation against r6
ppc.asm:9: Error: unsupported relocation against r1
...
```
Googling that error I found this [thread](https://stackoverflow.com/questions/30253742/error-unsupported-relocation-against-register-error-with-inline-ppc-assembl), which recommended that option.

## Running
Now we needed to run each of these newly assembled binaries, and provide the input and get the output from each. Enter `gdb-multiarch`!
### x86
This one was relatively simple, as, simply running `gdb ./x86` would do the trick. I could then set the values of each register with `set $eax=0xdeadbeef` and so on. I then added a breakpoint to the end of the code, allowed it to `continue` and then read out the final register values with `info registers`.

As an artifact of my initial approach, I had the x86 bit working in unicorn as well. That code is below, but, I could not get it to work on anything other than the plain x86 code.

```python
#!/usr/bin/env python
from unicorn import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.arm64_const import *
from unicorn.arm64_const import *

x86 = open('x86.o', 'rb').read()

ADDRESS    = 0x10000

mu = Uc(UC_ARCH_X86, UC_MODE_32)
mu.mem_map(ADDRESS, 2 * 1024 * 1024)
mu.mem_write(ADDRESS, x86)
mu.reg_write(UC_X86_REG_EAX, 0x4fedc591)
mu.reg_write(UC_X86_REG_EBX, 0xdb5c9333)
mu.reg_write(UC_X86_REG_ECX, 0xfa4e7919)
mu.reg_write(UC_X86_REG_EDX, 0x22551b9d)
mu.reg_write(UC_X86_REG_EDI, 0xfcb1c61f)
mu.reg_write(UC_X86_REG_ESI, 0xaf60af31)

mu.emu_start(ADDRESS, ADDRESS + len(x86))

r_eax = mu.reg_read(UC_X86_REG_EAX)
r_ebx = mu.reg_read(UC_X86_REG_EBX)
r_ecx = mu.reg_read(UC_X86_REG_ECX)
r_edx = mu.reg_read(UC_X86_REG_EDX)
r_edi = mu.reg_read(UC_X86_REG_EDI)
r_esi = mu.reg_read(UC_X86_REG_ESI)

print(">>> EAX = 0x%x" %r_eax)
print(">>> EBX = 0x%x" %r_ebx)
print(">>> ECX = 0x%x" %r_ecx)
print(">>> EDX = 0x%x" %r_edx)
print(">>> EDI = 0x%x" %r_edx)
print(">>> ESI = 0x%x" %r_edx)
```

```
eax            0x56d71dd3	0x56d71dd3
ecx            0x6b5c8090	0x6b5c8090
edx            0x82d8c374	0x82d8c374
ebx            0xc036d700	0xc036d700
esi            0x1f	0x1f
edi            0xffff8000	0xffff8000
```

### x86_64
This was the same as running the above, simply running `gdb ./x86_64`, setting each register to the output of the previous. Then, I again could set a breakpoint, and continue, the pull out the result values.

```
rax            0x0	0x0
rbx            0x92f	0x92f
rcx            0x1	0x1
rdx            0x2	0x2
rsi            0x0	0x0
rdi            0x1	0x1
```

### AArch64
The approach to running this one will be similar to the previous, but, would reqire emulating it in qemu, and, then attaching the `gdb-multiarch` debugger to that running code.

To run the code, I could simply do `qemu-aarch64-static -g 12000 arm`, which will emulate the code and pause it waiting for a connection from the debugger on port 12000.

To attach the debugger, I could simply run `gdb-multiarch`. Then, I provide GDB with the expected architecture and the target:
```
gef➤  set arch aarch64
The target architecture is assumed to be aarch64
gef➤  target remote 127.0.0.1:12000
```

After setting that all up, this program would act like a normal binary, and I could set registers, breakpoints, and run just like any native binary. I did this as before, providing the input from x86_64 to each ARM register:

```
x1             0xfffff703ffffffff	0xfffff703ffffffff
x2             0x0	0x0
x3             0xfffffffffffff703	0xfffffffffffff703
x4             0x0	0x0
x5             0xffffffff03f7ffff	0xffffffff03f7ffff
x6             0xfc080000	0xfc080000
```
### MIPS
Running MIPS is the same as before, except, using `qemu-mips-static` with the same argument structure. The MIPS process in GDB is the same as AArch64 as well, except, I had to update GDBs endianness since MIPS normally operates in big endian.
```
gef➤  set arch mips
The target architecture is assumed to be mips
gef➤  set endian big
The target is assumed to be big endian
gef➤  target remote 127.0.0.1:12000
```
I then provide the inputs as before, this time, mapping each aarch64 register to the output value `& 0xffffffff`. This resulted in the following:
```
s0       s1       s2       s3       s4       s5       s6       s7
R16  00000000 ffffff67 fffffd25 00000098 000002da 00eb8a48 00000b48 00000000  
```
### Power PC
Finally, PowerPC, which was the same as MIPS. The qemu command here was `qemu-ppc-static -g 12000 ppc`. As with MIPS, PPC was big endian, so I would run the same GDB setup commands.

```
gef➤  set arch powerpc:common
The target architecture is assumed to be powerpc:common
gef➤  set endian big
The target is assumed to be big endian
gef➤  target remote 127.0.0.1:12000
```
The setting breakpoints, running, and reading the output.
```
r1             0x0	0x0
r2             0xc2a	0xc2a
r3             0xffffff67	0xffffff67
r4             0x0	0x0
r5             0x0	0x0
r6             0x0	0x0
```

# Solution
The solution was the values of each PPC register XORd with each other. This final result concerned me a bit, but, did turn out to be correct.

```
>>> 0xc2a ^ 0xffffff67
4294964045
>>>
```
