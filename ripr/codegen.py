'''
CodeGen
'''
import sys
import os

try:
    from binaryninja import *
except:
    print "[+] Not running in BinaryNinja"

# ripr imports
import analysis_engine as ae
import dependency as dep

class codeSlice(object):
    '''
        A container class for a slice of code.
    '''
    def __init__(self, code, address):
        self.code_bytes = code
        self.address = address
        self.isNewPartition = False


class genwrapper(object):
    '''
        A storage area for different kinds of things we need to do to setup
        unicorn such that it can emulate the selected code.
        
        Regions we need to mmap
        Data we need to write
        Registers that need to be populated
        etc

        Args:
        Name: The name for this code
        engine: The analysis engine to be used.

        Attributes:
            mmap: Ranges we need to map
            data: List of data we need to copy into mappings
            code: List of codeSlice objects which need to be copied into memory
            
            arch: Architecture of this package
            saved_ranges:
            startaddr: Starting PC address for this package
            codelen: Length of code
            name: Name of the generated class
            conPass: Dictionary of applicable convenience passes (set by packager)
            impCallTargets: List of targets of imported calls to catch and hook
    '''
    def __init__(self, name, isFunc=True):

        self.mmap = {}
        # List of (address, data)
        self.data = []
        # List of codeSlice Objects
        self.code = []
        # Dict of regname:regvalue
        self.regs = {}
        self.arch = ''

        self.saved_ranges = []
        self.startaddr = 0
        self.codelen = 0
        self.name = name
        self.pagesize = self.get_pagesize()

        self.conPass = {}
        self.conPass['ret'] = False

        self.impCallTargets = []

        self.isFunc = isFunc
        
    def data_saved(self, addr): 
        return any(lowaddr <= addr <= highaddr for (lowaddr, highaddr) in self.saved_ranges)
    
    # Wrappers for manipulating data structures
    def add_mmap(self, addr, len=2 * 1024 * 1024):
        self.mmap[(addr & ~(self.pagesize - 1))] = len

    def add_data(self, data, addr):
        if (self.data_saved(addr)):
            print "[Warning] Trying to map data twice!"
            return
        self.data.append((addr, data))
        self.saved_ranges.append((addr, addr + len(data)))

    def add_code(self, cSlice):
        if (self.data_saved(cSlice.address)):
            print "[Warning] Trying to map data twice"
        self.code.append(cSlice)
        self.saved_ranges.append((cSlice.address, cSlice.address + len(cSlice.code_bytes)))

    def get_pagesize(self):
        if self.arch == 'x86':
            return 4096
        return 4096
        
    # Unicorn API generation helpers
    def generate_mmap(self, indent = 1):
        out = ''
        for addr in self.mmap:
            out += ' ' * (indent * 4) + "self.mu.mem_map(%s,%s)\n" % (hex(addr), hex(self.mmap[addr]))
        return out
    
    def generate_data_vars(self, indent = 1):
        out = ''
        for i in range(0, len(self.data)):
            out += ' ' * (indent * 4) + "self.data_%s = '%s'.decode('hex') \n" % (str(i), self.data[i][1].encode('hex'))
        return out

    def generate_code_vars(self, indent = 1):
        out = ''
        i = 0
        for cSlice in self.code:
            out += ' ' * (indent * 4) + "self.code_%s = '%s'.decode('hex') \n" % (str(i), cSlice.code_bytes.encode('hex'))
            i += 1
        return out

    
    def generate_stack_initialization(self, indent = 1):
        # We'll often need a stack pointer
        if self.arch == 'x86':
            self.add_mmap(0x7ffff000)
            out = ' ' * (indent * 4) + "self.mu.reg_write(UC_X86_REG_ESP, 0x7fffffff)\n"
        
        elif self.arch == 'x64':    # Same Stack mapping in case of 32-bit python/unicorn. May change later.
            self.add_mmap(0x7ffff000)
            out = ' ' * (indent * 4) + "self.mu.reg_write(UC_X86_REG_RSP, 0x7fffffff)\n"
        
        elif self.arch == 'arm':    
            self.add_mmap(0x7ffff000)
            out = ' ' * (indent * 4) + "self.mu.reg_write(UC_ARM_REG_SP, 0x7fffffff)\n"
        ## TODO Add support for other architectures supported by Unicorn and Binja 
        else:
            print "[ripr] Error, Unsupported Architecture"
        return out

    
    def generate_mem_writes(self, indent = 1):
        out = ''
        for i in range(0, len(self.data)):
            out += ' ' * (indent * 4) + "self.mu.mem_write(%s, self.data_%s)\n" % (hex(self.data[i][0]), i)
        for i in range(0, len(self.code)):
            out += ' ' * (indent * 4) + "self.mu.mem_write(%s, self.code_%s)\n" % (hex(self.code[i].address), i)
        return out
       
    def generate_emuinit(self, indent = 1):
        '''
            Decide how to initialize the emulator based on CPU Architecture.
        '''
        if self.arch == "x86":
            return ' ' * (indent * 4) + "self.mu = Uc(UC_ARCH_X86, UC_MODE_32)\n"
        # TODO Support Other Archs
        elif self.arch == "x64":
            return ' ' * (indent * 4) + "self.mu = Uc(UC_ARCH_X86, UC_MODE_64)\n"
            
        elif self.arch == "arm":
            return ' ' * (indent * 4) + "self.mu =  Uc(UC_ARCH_ARM, UC_MODE_ARM)\n"
        
        elif self.arch == "arm64":
            return ' ' * (indent * 4) + "self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)\n"
            
            
    def generate_emustart(self, indent = 1):
        out = ' ' * (indent * 4) + "try:\n"
        out +=  ' ' * ((indent + 1) * 4) + "self.mu.emu_start(startaddr, 0)\n"
        out += ' ' * (indent * 4) + "except Exception as e:\n"
        if self.isFunc:
            out += self.generate_return_guard(indent=indent+1)
        else:
            out += ' ' * (indent + 1 ) * 4 + "pass\n"
        return out

    def generate_start_unicorn_func(self, indent = 1):
        '''
            This function wraps starting the unicorn emulator and dealing with exceptions if applicable.
        '''
        decl = ' ' * (indent * 4) + 'def _start_unicorn(self, startaddr):\n' 
        body = self.generate_emustart(indent=2)
        return decl+body 

    def generate_return_guard_marker(self, indent=1):
        '''
            Generate code that will result in the emulator returning to a marker value at the end of a 
            successfull function emulation. This is caught by code in generate_return_guard and indicates
            that the function behaved normally.
        '''
        out = ''
        if self.arch in ['x86', 'x64']:
            out += ' ' * (indent *4) + "self.mu.mem_write(0x7fffffff, '\\x01\\x00\\x00\\x00')\n"
        elif self.arch == 'arm':
            out += ' ' * (indent *4) + "self.mu.reg_write(UC_ARM_REG_LR, 0x4)\n"
        else:
            print "Unsupported Arch"
        return out

    def generate_restore_exec(self, indent=1):
        '''
            Generate code that will adjust the cpu context so it matches expected behaviour after
            a hooked call.
        '''
        out = ''
        if self.arch == 'x64':
            out += ' ' * (indent * 4) + "self.mu.reg_write(UC_X86_REG_RSP, self.mu.reg_read(UC_X86_REG_RSP) + 8)\n"
            out += ' ' * (indent * 4) + "self._start_unicorn(retAddr)\n"
        elif self.arch == 'x86':
            out += ' ' * (indent * 4) + "self.mu.reg_write(UC_X86_REG_ESP, self.mu.reg_read(UC_X86_REG_ESP) + 4)\n"
            out += ' ' * (indent * 4) + "self._start_unicorn(retAddr)\n"
        elif self.arch == 'arm':
            out += ' ' * (indent * 4) + "self._start_unicorn(retAddr)\n"
            pass
        else:
            print "Unsupported Arch"

        return out

    def generate_hook_lookup(self, indent=1):
        if self.arch == 'x64':
            retAddr = ' ' * (indent * 4) + "retAddr = struct.unpack(\"<q\", self.mu.mem_read(self.mu.reg_read(UC_X86_REG_RSP), 8))[0]\n"
        elif self.arch == 'x86':
            retAddr = ' ' * (indent * 4) + "retAddr = struct.unpack(\"<i\", self.mu.mem_read(self.mu.reg_read(UC_X86_REG_ESP), 4))[0]\n"
        elif self.arch == 'arm':
            retAddr = ' ' * (indent * 4) + "retAddr = self.mu.reg_read(UC_ARM_REG_LR)\n"

        else:
            print "Unsupported Architecture"
            retAddr = ' ' * (indent * 4) + "retAddr = 0\n"
            
        chk_hookdict = ' '  * (indent * 4) + "if retAddr in self.hookdict.keys():\n"
        getattr_call = ' ' * ( (indent+1) * 4) + "getattr(self, self.hookdict[retAddr])()\n"

        restore = self.generate_restore_exec(indent=indent+1)
        return retAddr + chk_hookdict + getattr_call + restore

    def generate_return_guard(self, indent=1):
        '''
            Generate code to catch the "crash" that will happen after a packaged function hits a 
            ''return'' instruction or imported call. We use 0x1 as a marker to say the function has hit a return as 
            expected.
        '''
        out = ''
        if (self.arch == 'x64'):
            out += ' ' * (indent * 4) + "if self.mu.reg_read(UC_X86_REG_RIP) == 1:\n"
        elif (self.arch == 'x86'):
            out += ' ' * (indent * 4) + "if self.mu.reg_read(UC_X86_REG_EIP) == 1:\n"
        elif (self.arch == 'arm'):
            out += ' ' * (indent * 4) + "if self.mu.reg_read(UC_ARM_REG_PC) == 4:\n"
        else:
            print "[ripr] Unsupported Arch..."
        
        # Return if PC has landed on the marker value
        out += ' ' * ((indent + 1) * 4) + "return\n"
        
        # Check if this crash is the result of an imported Call and execute the hook if applicable
        if (self.impCallTargets):
            out += self.generate_hook_lookup(indent=indent)

        # Raise original exception if PC is not equal to the appropriate marker value or imported call marker
        out += ' ' * (indent * 4) + "else:\n"
        out += ' ' * ((indent + 1) * 4) + "raise e"

        return out + "\n"

    def generate_return_conv(self, indent=1):
        '''
            Generate code for the ''return-value recovery'' convenience pass. 
            The 'run()' function will return whatever the architecture specific return register typically
            is rather than requiring the user to manually query the emulator state.
        '''
        if self.arch == 'x64':
            return ' ' * (indent * 4) + "return self.mu.reg_read(UC_X86_REG_RAX)\n"
        elif self.arch == 'x86':
            return ' ' * (indent * 4) + "return self.mu.reg_read(UC_X86_REG_EAX)\n"
        elif self.arch == 'arm':
            return ' ' * (indent * 4) + "return self.mu.reg_read(UC_ARM_REG_R0)\n"
        else:
            print '[ripr] Unsupported Arch'

   
    def generate_run_functions(self, indent = 1):
        # If this is partitioned code, generate multiple run functions for each partition
        out = ''
        decl = ' ' * 4 + "def run(self):\n"

        stk = self.generate_stack_initialization(indent=2)
        marker = self.generate_return_guard_marker(indent=2)
        emus = ' ' * ((indent) * 4) + "self._start_unicorn(%s)\n" % (hex(self.startaddr))

        out += decl + stk + marker + emus
        # Check for return value recovery convenience 
        if (self.conPass['ret'] == True):
            out += self.generate_return_conv(indent=2)

        return out

    def imp_consts(self):
        '''
            Return an import string depending on what arch you are using.
        '''
        if self.arch in ('x86', 'x64'):
            return "from unicorn.x86_const import *\n\n"
        elif self.arch == 'arm':
            return "from unicorn.arm_const import *\n\n"
        elif self.arch == 'arm64':
            return "from unicorn.arm64_const import *\n\n"
        elif self.arch in ('mips32', 'mips64'):
            return "from unicorn.mips_const import *\n\n"
        elif self.arch in ('m68k'):
            return "from unicorn.m68k_const import *\n\n"
        elif self.arch in ('sparc'):
            return "from unicorn.sparc_const import *\n\n"
            
    # Code "Builders"
    
    def generate_default_hookFunc(self, name, indent=1):
        '''
            The default python hook for imported calls should do nothing.
        '''
        out = ' ' * (indent * 4) + """def hook_%s(self):
        pass\n""" % name
        return out
        
    def _build_impCall_hook_dict(self, indent=1):
        '''
            Build a dictionary of return address --> hook function for dynamic
            imported call handling. 
        '''
        
        ret = ''
        out = {}
        build_funcs = []
        # Get a list of names for hook functions
        for impCall in self.impCallTargets:
            if str(impCall.symbol) not in build_funcs:
                build_funcs.append(str(impCall.symbol))
            
            out[impCall.address + impCall.inst_len] = "hook_%s" % str(impCall.symbol)

        # Generate stubs for the hooked functions
        for func in build_funcs:
            ret += self.generate_default_hookFunc(func)

        return (ret, out)

    def generate_hookdict(self, hookd, indent=1):
        return ' ' * (indent * 4) + "self.hookdict = %s\n" % hookd


    def generate_class(self):
        '''
            Wrap this chunk of code into a python class
        '''
        self.code = sorted(self.code, key=lambda x: x.address)
        
        # Static Strings
        defn = "class %s(object):\n" % (self.name)
        imp = "from unicorn import *\n" + self.imp_consts() + "import struct\n"
        init = ' ' * 4 + "def __init__(self):\n"
        run = ' ' * 4 + "def run(self):\n"
        
        # Dyanmic Strings
        emuinit = self.generate_emuinit(indent = 2)
        codevars = self.generate_code_vars(indent = 2) + "\n"
        datavars = self.generate_data_vars(indent = 2) + "\n"

        # Generate run function 
        runfns = self.generate_run_functions(indent=2) 

        if (self.impCallTargets):
            # Build list of Return Addresses to Hooked Functions
            hooks = self._build_impCall_hook_dict()
            hookdict = self.generate_hookdict(hooks[1], indent=2)
            hooks = hooks[0]
        else:
            hooks = ''
            hookdict = ''
        
        # mmaps and writes must be generated at the end
        mmaps = self.generate_mmap(indent = 2) + "\n"
        writes = self.generate_mem_writes(indent = 2) + "\n"

        start_unicorn = self.generate_start_unicorn_func()

        # Put the pieces together
        self.final = imp + defn + init + emuinit + codevars + datavars + mmaps + writes + hookdict + hooks + start_unicorn + runfns +"\n"
