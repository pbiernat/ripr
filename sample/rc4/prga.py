from unicorn import *
from unicorn.x86_const import *

import struct

from unicorn import *
from unicorn.x86_const import *

import struct
class PRGA(object):
    def __init__(self):
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.code_0 = '554889e548897de8488975e0488b45e80fb6000fb6c08945fc488b45e00fb610488b45e888108b45fc89c2488b45e08810905dc3'.decode('hex') 
        self.code_1 = '554889e54883ec4048897dd8488975d0488955c8c745e400000000c745e80000000048c745f000000000488b45d04889c7e867fdffff488945f8e9e50000008b45e48d500189d0c1f81fc1e81801c20fb6d229c289d08945e48b45e44863d0488b45d84801d00fb6000fb6d08b45e801c289d0c1f81fc1e81801c20fb6d229c289d08945e88b45e84863d0488b45d84801c28b45e44863c8488b45d84801c84889d64889c7e849feffff8b45e44863d0488b45d84801d00fb6000fb6d08b45e84863c8488b45d84801c80fb6000fb6c001d048980fb6d0488b45d84801d00fb6000fb6c08945ec488b55c8488b45f04801d0488b4dd0488b55f04801ca0fb60a8b55ec89ce31d6488b150f082000488b4df083e1034801ca0fb61231f28810488345f001488b45f0483b45f80f820dffffffb800000000c9c3'.decode('hex') 

        self.data_0 = '00000000000000000000000000000000540a400000000000'.decode('hex') 

        self.mu.mem_map(0x400000L,0x4000)
        self.mu.mem_map(0x601000L,0x4000)
        self.mu.mem_map(0x7ffff000,0x200000)
        self.mu.mem_map(0x1000 * 1, 0x1000)
        self.mu.mem_map(0x1000 * 2, 0x1000)
        self.mu.mem_map(0x1000 * 3, 0x1000)
        self.mu.mem_map(0x1000 * 4, 0x1000) # Missed mapping

        self.mu.mem_write(0x601040L, self.data_0) # obfuscator
        self.mu.mem_write(0x400626L, self.code_0) # swap()
        self.mu.mem_write(0x400733L, self.code_1)
        self.mu.mem_write(0x400a54L, "4142434400".decode('hex'))
        self.mu.mem_write(0x4004d0L, "ff25410b2000".decode('hex'))

        self.hookdict = {4196201L: 'hook_strlen'}

    def hook_strlen(self):
        arg = self.mu.reg_read(UC_X86_REG_RDI)
        arg0 = arg
        mem = self.mu.mem_read(arg, 1)
        while mem[0] != 0:
            arg+=1
            mem = self.mu.mem_read(arg, 1)
        print "strlen(): %d" % (arg-arg0)
        self.mu.reg_write(UC_X86_REG_RAX, arg-arg0)
        return arg-arg0

    def _start_unicorn(self, startaddr):
        try:
            self.mu.emu_start(startaddr, 0)
        except Exception as e:
            if self.mu.reg_read(UC_X86_REG_RIP) == 1:
                return
            retAddr = struct.unpack("<q", self.mu.mem_read(self.mu.reg_read(UC_X86_REG_RSP), 8))[0]
            print "%08x" % retAddr
            if retAddr in self.hookdict.keys():
                getattr(self, self.hookdict[retAddr])()
                self.mu.reg_write(UC_X86_REG_RSP, self.mu.reg_read(UC_X86_REG_RSP) + 8)
                self._start_unicorn(retAddr)
            else:
                print "RIP: %08X" % self.mu.reg_read(UC_X86_REG_RIP)  # 0x4007dd: mov eax, dword [rbp-0x1c]
                print "EAX: %08X" % (self.mu.reg_read(UC_X86_REG_EAX))
                raise e
    def run(self, arg_0, arg_1, arg_2):
        self.mu.reg_write(UC_X86_REG_RSP, 0x7fffff00)
        self.mu.mem_write(0x7fffff00, '\x01\x00\x00\x00')
        argAddr_0 = (1 * 0x1000)
        self.mu.mem_write(argAddr_0, arg_0)
        self.mu.reg_write(UC_X86_REG_RDI, argAddr_0)
        argAddr_1 = (2 * 0x1000)
        self.mu.mem_write(argAddr_1, arg_1)
        self.mu.reg_write(UC_X86_REG_RSI, argAddr_1)
        argAddr_2 = (3 * 0x1000)
        self.mu.mem_write(argAddr_2, arg_2)
        self.mu.reg_write(UC_X86_REG_RDX, argAddr_2)
        self._start_unicorn(0x400733)
        print repr(self.mu.mem_read(argAddr_2, 4))
        return self.mu.reg_read(UC_X86_REG_RAX)



class KSA(object):
    def __init__(self):
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.code_0 = '554889e548897de8488975e0488b45e80fb6000fb6c08945fc488b45e00fb610488b45e888108b45fc89c2488b45e08810905dc3'.decode('hex') 
        self.code_1 = '554889e54883ec2048897de8488975e0488b45e84889c7e85afeffff8945fcc745f000000000c745f400000000eb168b45f44863d0488b45e04801d08b55f488108345f401817df4ff0000007ee1c745f800000000eb728b45f84863d0488b45e04801d00fb6000fb6d08b45f08d0c028b45f899f77dfc89d04863d0488b45e84801d00fb6000fbec08d140189d0c1f81fc1e81801c20fb6d229c289d08945f08b45f04863d0488b45e04801c28b45f84863c8488b45e04801c84889d64889c7e807ffffff8345f801817df8ff0000007e85b800000000c9c3'.decode('hex') 


        self.mu.mem_map(0x400000L,0x4000)
        self.mu.mem_map(0x7ffff000,0x200000)
        self.mu.mem_map(0x1000 * 1, 0x1000)
        self.mu.mem_map(0x1000 * 2, 0x1000)

        self.mu.mem_write(0x400626L, self.code_0)
        self.mu.mem_write(0x40065aL, self.code_1)

        self.hookdict = {4195958L: 'hook_strlen'}
    def hook_strlen(self):
        pass
    def _start_unicorn(self, startaddr):
        try:
            self.mu.emu_start(startaddr, 0)
        except Exception as e:
            if self.mu.reg_read(UC_X86_REG_RIP) == 1:
                return
            retAddr = struct.unpack("<q", self.mu.mem_read(self.mu.reg_read(UC_X86_REG_RSP), 8))[0]
            if retAddr in self.hookdict.keys():
                getattr(self, self.hookdict[retAddr])()
                self.mu.reg_write(UC_X86_REG_RSP, self.mu.reg_read(UC_X86_REG_RSP) + 8)
                self._start_unicorn(retAddr)
            else:
                raise e
    def run(self, arg_0, arg_1):
        self.mu.reg_write(UC_X86_REG_RSP, 0x7fffff00)
        self.mu.mem_write(0x7fffff00, '\x01\x00\x00\x00')
        argAddr_0 = (1 * 0x1000)
        self.mu.mem_write(argAddr_0, arg_0)
        self.mu.reg_write(UC_X86_REG_RDI, argAddr_0)
        argAddr_1 = (2 * 0x1000)
        self.mu.mem_write(argAddr_1, arg_1)
        self.mu.reg_write(UC_X86_REG_RSI, argAddr_1)
        self._start_unicorn(0x40065a)
        return self.mu.mem_read(argAddr_1,256)
        # return self.mu.reg_read(UC_X86_REG_RAX)

key="key"
S=" "*256
cipher=""
plain="test"

ksa=KSA()
S=str(ksa.run(key,S))
print repr(S)
prga=PRGA()
prga.run(S,plain,cipher)
print repr(cipher)
