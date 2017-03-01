'''
    This code should encapsulate product specific API's so that they 
    can be accessed in other components cleanly.
'''

# Try to import stuff.
try:
    from binaryninja import *
except:
    print "[!!] Not running in Binary Ninja"

import sys
import gui
import codegen

def get_engine(*args):
    '''
        Return an instance of the correct analysis engine class.
    '''
    print args
    if ("binaryninja" in sys.modules.keys()):
        return bn_engine(args[0])
    


class aengine(object):
    def __init__(self):
        pass

    def find_section(self, addr):
        '''
            Function should find what segment/section $addr is in and return a tuple
            (StartAddress, Endaddress, Segment Name)
            Error: Return -1
        '''
        pass

    def get_arch(self):
        '''
            Function should return a string of the architecture of the currently loaded binary.
            Architecture should be one of:
            'x86'
            'x64'
            'arm'
            'mips'
        '''
        pass

    def get_function_bytes(self, address=None, name=None):
        '''
            Function should return a dictionary of address:string pairs where address
            is a starting address and string is a string of bytes of the function at that location.

            This allows for handling functions that are non-contiguous in memory.
        '''
        pass

    def get_page_bytes(self, address):
        '''
            Funtion should return a string of bytes from the page where address
            is located. 
        '''
        pass

    def get_nop_opcode(self, arch):
        '''
            Function should return a string corresponding to a NOP on the specified
            architecture.
        '''
        pass

    def get_region_bytes(self, start, end):
        '''
            Function should return a tuple (address, string) where address
            is the starting address of the region and string contains the bytes 
            between start and end, inclusive.
        '''
        return (start, self.read_bytes(start, end - start))
    
    def read_bytes(self, address, len):
        '''
            Function should return a string containing
            $len bytes at $address.
        '''
        pass

class bn_engine(aengine):
    '''
        This class should encapsulate all binary-ninja api calls cleanly. 
        Comments in this class relate to why a certain function is implemented the way it is,
        mostly relating to Binary Ninja specifics. Descriptions of what a function should do
        are in the aengine class.
    '''

    def __init__(self, view):
        # We will need a BinaryViewType.
        self.bv = view
        aengine.__init__(self)

    def read_bytes(self, address, len):
        return self.bv.read(address, len)

    def get_arch(self):
        '''
            ripr uses its own architecture names that map onto Unicorn architectures. 
            These can be different from Binary Ninja names, so they are explicitly mapped
            into the ripr names, even if they are the same in some cases.
        '''
        print self.bv.arch.name
        if (self.bv.arch.name == 'x86'):
            return 'x86'
        elif (self.bv.arch.name == 'x86_64'):
            return 'x64'
        # TODO Other ARM archs that we can deal with as 'arm'
        elif (self.bv.arch.name == 'armv7'):
            return 'arm'
    

    def get_function_bytes(self, address=None, name=None):
        ''' 
            Binary Ninja does not seem to assume Functions are contiguous; rather they 
            are treated as a collection of basic blocks. 
        '''
        print "[ripr] Inside get_function_bytes()"
        if (address != None):
            fobj = self.bv.get_function_at(address)
        elif (name != None):
            print "[ripr] TODO"
            return
        else:
            print "[ripr] No arguments supplied to get_function_bytes"
            return None
        # Sort the basic blocks in ascending order 
        bblist = sorted(fobj.basic_blocks, key=lambda x: x.start)
        map(lambda bb: bb.set_user_highlight(HighlightStandardColor.BlackHighlightColor), bblist)
        # Create units of contiguous blocks
        clist = [[bblist[0]]]
        for bb in bblist[1:]:
            if (bb.start == clist[-1][-1].end):
                clist[-1].append(bb)
            else:
                clist.append([bb])
        # Print out the list if the function is not contiguous
        if (len(clist) > 1):
            print clist

        # Create a return list in the expected format from the contiguous units.
        retdir = {unit[0].start : codegen.codeSlice(self.read_bytes(unit[0].start, unit[-1].start - unit[0].start + unit[-1].length), unit[0].start) for unit in clist}
        return retdir

    def get_page_bytes(self, address):
        # Should get this dynamically if possible based on arch/mode/etc
        pagesize = self.get_page_size()
        pageaddr = (address & ~(pagesize - 1))
        return self.read_bytes(pageaddr, pagesize)

    def get_page_size(self):
        return 4096

    def get_region_bytes(self, start, end):
        return (start, self.read_bytes(start, end-start))
        
    def get_nop_opcode(self):
        return self.bv.arch.assemble('nop')[0]

    def generate_invalid_access(self, address, arch, size=None):
        '''
            Generates an invalid memory access for use in function hooking.
            pad to size if applicable
        '''
        if arch in ['x86', 'x64']:
            if (size):
                opcodes = self.bv.arch.assemble('mov al, [%s]' % address)[0]
                nop = self.get_nop_opcode()
                if len(opcodes) >= size:
                    return opcodes
                return opcodes + nop * (size - len(opcodes))
            else:
                return self.bv.arch.assemble('mov al, [%s]' % address)[0]
