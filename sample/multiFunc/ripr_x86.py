from unicorn import *
from unicorn.x86_const import *

import struct
class x86_test(object):
    def __init__(self):
        self.mu = Uc(UC_ARCH_X86, UC_MODE_32)
        self.code_0 = '5589e583ec0883ec0c6880850408e8c2feffff83c4108b45080faf450cc9c3'.decode('hex') 
        self.code_1 = '5589e583ec0883ec0c688f850408e8a3feffff83c4108b55088b450c01d0c9c3'.decode('hex') 
        self.code_2 = '5589e55383ec0483ec0c689e850408e882feffff83c41083ec086a026a01e8bdffffff83c41089c383ec086a046a03e88dffffff83c41001d88b5dfcc9c3'.decode('hex') 

        self.data_0 = '0300000001000200496e736964652066756e635f330a00496e736964652066756e635f320a00496e736964652066756e635f310a00416e737765723a2025640a00'.decode('hex') 

        self.mu.mem_map(0x8048000L,0x200000)
        self.mu.mem_map(0x7ffff000,0x200000)

        self.mu.mem_write(0x8048578L, self.data_0)
        self.mu.mem_write(0x804843bL, self.code_0)
        self.mu.mem_write(0x804845aL, self.code_1)
        self.mu.mem_write(0x804847aL, self.code_2)

        self.hookdict = {134513742L: 'hook_puts', 134513773L: 'hook_puts', 134513806L: 'hook_puts'}
    def hook_puts(self):
        pass
    def _start_unicorn(self, startaddr):
        try:
            self.mu.emu_start(startaddr, 0)
        except Exception as e:
            if self.mu.reg_read(UC_X86_REG_EIP) == 1:
                return
            retAddr = struct.unpack("<i", self.mu.mem_read(self.mu.reg_read(UC_X86_REG_ESP), 4))[0]
            if retAddr in self.hookdict.keys():
                getattr(self, self.hookdict[retAddr])()
                self.mu.reg_write(UC_X86_REG_ESP, self.mu.reg_read(UC_X86_REG_ESP) + 4)
                self._start_unicorn(retAddr)
            else:
                raise e
    def run(self):
        self.mu.reg_write(UC_X86_REG_ESP, 0x7fffffff)
        self.mu.mem_write(0x7fffffff, '\x01\x00\x00\x00')
        self._start_unicorn(0x804847a)
        return self.mu.reg_read(UC_X86_REG_EAX)

