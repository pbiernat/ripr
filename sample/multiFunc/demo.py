from ripr_x64 import *
from ripr_x86 import *
from ripr_arm import *

import struct
class test1(x64_test):
    def hook_puts(self):
        print "In Puts"
        arg = self.mu.reg_read(UC_X86_REG_RDI)
        mem = self.mu.mem_read(arg, 0x200)
        print "%s" % (mem.split("\x00")[0])

class test2(x86_test):
    def hook_puts(self):
        print "In Puts"
        esp = self.mu.reg_read(UC_X86_REG_ESP)
        arg = self.mu.mem_read(esp+4, 0x4)
        arg = struct.unpack("<i", arg)[0]
        mem = self.mu.mem_read(arg, 0x200)
        print "%s" % (mem.split("\x00")[0])

class test3(arm_test):
    def hook_puts(self):
        print "In Puts"
        arg = self.mu.reg_read(UC_ARM_REG_R0)
        mem = self.mu.mem_read(arg, 0x30)
        print "%s" % (mem.split("\x00")[0])
    



print "======================================================="
print "[+] Starting x64 emulation"
print "======================================================="
x = test1()
print x.run()

raw_input()

print "======================================================="
print "[+] Starting x86 emulation"
print "======================================================="
x = test2()
print x.run()

raw_input()

print "======================================================="
print "[+] Starting ARM emulation"
print "======================================================="
x = test3()
print x.run()
