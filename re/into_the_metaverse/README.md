# Into The Metaverse (Reverse Engineering 450)
TODO: Description and images to come later!
Solves: 27
# Analysis
This challenge was about a virtual machine like language that was used to obfuscate the logic in the binary. I first noticed their internal structure implementing the language:
```c
struct {
    char * executionPtr;
    char * stackPtr;
    char opcodes[0x800];
    char stack[0x800];
};
```
As the program executed, the various pointers would be updated, and, the program would also modify the data located in both the stack and the opcodes storage segments, which made it sort of like a self unpacking feature.


I found the following when I started reversing which opcodes did what:
* Opcode 0x8a
> This opcode appeared at first glance to be rather complex compared to the others, so, I ignored it and came back later on. I discovered this one was executed near the end of the logic and essentially is what implemented the loop.

* Opcode 0xb2
> This opcode is similar to the above, I ignored it, and never needed it throughout my analysis.

* Opcode 0xd7
> I called this opcode the second shift operation. It would load a word from the internal stack pointer, shift around the MSB, and store it back on the stack.

* Opcode 0xf0
> I called this the XOR operation. This would take two words off the stack, XOR them together, then store the result back on the stack.

* Opcode 0xc1
> Move to storage. Would take two words off the stack, and would take the second one, multiply by two, and set the word at that offset in the storage to the first one.

* Opcode 0x93
> Store word. This opcode would push a word from the stack to the main program memory. It would take a word argument which represented the offset to the data to store.

* Opcode 0xa4
> Compare function. Would take two words from the stack, compare them, and push the result onto the stack.

* Opcode 0x90
> This was a return or NOP. Fitting choice of byte.

* Opcode 0x38
> Would reverse two arguments on the stack.

* Opcode 0x51
> Subtraction operation. Took two words off the stack, moved the stack back, subtracted the first from the second, then pushed that to the stack.

* Opcode 0x62
> Check flag function. Would check if the words at the stack pointer was 0x01, if it was, would print success, else fail.

* Opcode 0x43
> I called this one the add operation. It would take two words off of the stack, add them together, and store the result back on the stack.

* Opcode 0x12
> I wasn't sure what to call this opcode. It appeared to copy the word at the stack pointer to right one word, and update the stack pointer to match.

* Opcode 0x22
> I called this opcode the shift operation. It would load a word from the internal stack pointer, shift around the LSB, and store it back on the stack.

* Opcode 0x02
> Loads from storage, would take a word from the stack pointer, and set the stack pointer to the word at that location.


# Approach
To solve this one, I did a bit of static analysis to understand what the various opcodes where, what they did, how they were called, and so on.


I then used dynamic analysis to extract the logic that was used to validate the flag. The binary had some logic to unpack the virtual machine code itself, then it would transform the flag input to an encoded version, and finally compare the two.

To extract the logic, I noticed that the opcode `A4` was only used when running the flag comparison, so, I added a breakpoint to that function and let it run up until that. I then stepped through the code a bit, and noticed that the bytecode was not changing and simply repeating over my input transforming it into the encoded form, perfect, I copied this section out.

Finally, I replicated the logic I extracted in Python using the notes above, then used it to generate the possible pairs of inputs to outputs. And from there, I compared the stored and encoded flag to get the real input value.

# Solution
Unfortunately, my solution script and notes disappeared on me (due to some storage issues I had during the CTF).
