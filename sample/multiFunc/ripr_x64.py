from unicorn import *
from unicorn.x86_const import *

import struct
class x64_test(object):
    def __init__(self):
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.code_0 = '554889e54883ec10897dfc8975f8bfa4064000e8b2feffff8b45fc0faf45f8c9c3'.decode('hex') 
        self.code_1 = '554889e54883ec10897dfc8975f8bfb3064000e891feffff8b55fc8b45f801d0c9c3'.decode('hex') 
        self.code_2 = '554889e5534883ec08bfc2064000e874feffffbe02000000bf01000000e8bcffffff89c3be04000000bf03000000e88affffff01d84883c4085b5dc3'.decode('hex') 

        self.data_0 = '01000200496e736964652066756e635f330a00496e736964652066756e635f320a00496e736964652066756e635f310a00416e737765723a2025640a00'.decode('hex') 

        self.mu.mem_map(0x400000L,0x200000)
        self.mu.mem_map(0x7ffff000,0x200000)

        self.mu.mem_write(0x4006a0L, self.data_0)
        self.mu.mem_write(0x400566L, self.code_0)
        self.mu.mem_write(0x400587L, self.code_1)
        self.mu.mem_write(0x4005a9L, self.code_2)

        self.hookdict = {4195772L: 'hook_puts', 4195710L: 'hook_puts', 4195743L: 'hook_puts'}
    def hook_puts(self):
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
    def run(self):
        self.mu.reg_write(UC_X86_REG_RSP, 0x7fffffff)
        self.mu.mem_write(0x7fffffff, '\x01\x00\x00\x00')
        self._start_unicorn(0x4005a9)
        return self.mu.reg_read(UC_X86_REG_RAX)

