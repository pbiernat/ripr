'''
    This code should encapsulate product specific API's so that they 
    can be accessed in other components cleanly.
'''

# Try to import stuff.
try:
    from binaryninja import *
except:
    print ("[!!] Not running in Binary Ninja")

try:
    import r2pipe
except:
    print ("[!!] Not running in Radare2")

import json
import re
import sys
from .codegen import *
from binascii import unhexlify

def get_engine(*args):
    '''
        Return an instance of the correct analysis engine class.
    '''
    if ("r2pipe" in sys.argv[0]):
        return radare2_engine(r2pipe.open())
    
    if ("binaryninja" in sys.modules.keys()):
        return bn_engine(args[0])


    raise (ValueError, "No analysis engine found!")
    


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

    def get_nop_opcode(self):
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

    def get_imports(self):
        raise NotImplementedError

    def get_instruction_length(self, address):
        raise NotImplementedError

    def get_data_symbols(self):
        raise NotImplementedError

    def get_strings(self):
        raise NotImplementedError

    def get_refs_to(self, address):
        raise NotImplementedError

    def function_contains_addr(self, func_addr, testAddr):
        raise NotImplementedError

    def get_page_size(self):
        raise NotImplementedError

    def generate_invalid_access(self, address, arch, size=None):
        raise NotImplementedError

    def branches_from_func(self, address, callCallback, branchCallback):
        raise NotImplementedError

    def scan_potential_pointers(self, func_addr):
        raise NotImplementedError

    def is_plausible_pointer(self, candidate_ptr):
        raise NotImplementedError

    def highlight_instr(self, func_addr, instrAddr, color):
        pass

    def add_comment(self, func_addr, instrAddr, comment):
        pass

    def display_info(self, info1, info2):
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
        print (self.bv.arch.name)
        if (self.bv.arch.name == 'x86'):
            return 'x86'
        elif (self.bv.arch.name == 'x86_64'):
            return 'x64'
        elif (self.bv.arch.name == 'armv7'):
            return 'arm'

    def mark_gathered_basic_block(self, address):
        fobj = self.bv.get_functions_containing(address)[0]
        if (fobj == None):
            print ("FOBJ IS NONE")
        bb = fobj.get_basic_block_at(address)
        bb.highlight = HighlightStandardColor.BlackHighlightColor

        fobj.set_comment_at(bb.start, "[ripr] Basic Block will be included in package")

    def clean_gathered_basic_block(self, address):
        fobj = self.bv.get_functions_containing(address)[0]
        bb = fobj.get_basic_block_at(address)

        bb.highlight = HighlightStandardColor.NoHighlightColor
        fobj.set_comment_at(bb.start, '')
   
    def get_basic_block_bytes(self, address):
        bb = self.bv.get_basic_blocks_at(address)
        if len(bb) != 1:
            print ("[ripr] Address belongs to more than one basic block!")

        bb = bb[0]
        return {bb.start: codeSlice(self.read_bytes(bb.start, bb.end-bb.start), bb.start)}

    def get_function_bytes(self, address=None, name=None):
        ''' 
            Binary Ninja does not seem to assume Functions are contiguous; rather they 
            are treated as a collection of basic blocks. 
        '''
        print ("[ripr] Inside get_function_bytes()")
        if (address != None):
            fobj = self.bv.get_function_at(address)
        elif (name != None):
            print ("[ripr] TODO")
            return
        else:
            print ("[ripr] No arguments supplied to get_function_bytes")
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
            print (clist)

        # Create a return list in the expected format from the contiguous units.
        retdir = {unit[0].start : codeSlice(self.read_bytes(unit[0].start, unit[-1].start - unit[0].start + unit[-1].length), unit[0].start) for unit in clist}
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

    def get_imports(self):
        return {self.bv.symbols[sym].address : self.bv.symbols[sym].name for sym in self.bv.symbols if self.bv.symbols[sym].type == SymbolType.ImportedFunctionSymbol}


    def get_instruction_length(self, address):
        return self.bv.get_instruction_length(address)

    def find_llil_block_from_addr(self, address):
        fobj = self.bv.get_functions_containing(address)
        if len(fobj) > 1:
            print ("[ripr] Multiple Functions contain this address!!")
            return None
        fobj = fobj[0]
        bbindex = fobj.get_basic_block_at(address).index
        return fobj.low_level_il.basic_blocks[bbindex]

    def find_mlil_block_from_addr(self, address):
        fobj = self.bv.get_functions_containing(address)
        if len(fobj) > 1:
            print ("[ripr] Multiple Functions contain this address!!")
            return None
        fobj = fobj[0]
        bbindex = fobj.get_basic_block_at(address).index
        try:
            ret = fobj.medium_level_il.basic_blocks[bbindex]
            return ret
        except:
            return None

    def branches_from_block(self, block, callCallback, branchCallback):
        for il_inst in block:
            if (il_inst.operation == LowLevelILOperation.LLIL_CALL):
                callCallback(il_inst.dest.value, il_inst.address)
            # Check Jump targets
            elif (il_inst.operation in [LowLevelILOperation.LLIL_JUMP,\
                                        LowLevelILOperation.LLIL_JUMP_TO,\
                                        LowLevelILOperation.LLIL_GOTO]):
                branchCallback(il_inst.dest, il_inst.address)
            else:
                pass

    def branches_from_func(self, address, callCallback, branchCallback):
        fobj = self.bv.get_function_at(address)
        for block in fobj.low_level_il:
            self.branches_from_block(block, callCallback, branchCallback)

    def get_data_symbols(self):
        for sym in self.bv.symbols:
            if self.bv.symbols[sym].type == 'DataSymbol':
                yield sym.address()

    def get_strings(self):
        for st in self.bv.strings:
            yield (st.start, st.length)

    def get_refs_to(self, address):
        fobj = self.bv.get_function_at(address)
        for ref in self.bv.get_code_refs(address):
            yield ref.address

    def function_contains_addr(self, func_addr, testAddr):
        fobj = self.bv.get_function_at(func_addr)
        return (fobj.get_basic_block_at(testAddr) != None)

    def scan_potential_pointers_bb(self, il_block, fobj):
        for il_inst in il_block:
           # We are only interested in data references here.
            if il_inst.operation in [LowLevelILOperation.LLIL_CALL, \
                                     LowLevelILOperation.LLIL_JUMP, \
                                     LowLevelILOperation.LLIL_GOTO, \
                                     LowLevelILOperation.LLIL_IF,   \
                                     LowLevelILOperation.LLIL_JUMP_TO]:
                continue

            constants = fobj.get_constants_referenced_by(il_inst.address)
            # Check if constant is a likely pointer
            for const in constants:
                yield const.value, il_inst.address
            # Memory things
            if il_inst.operation in [LowLevelILOperation.LLIL_LOAD,\
                                     LowLevelILOperation.LLIL_STORE,\
                                     LowLevelILOperation.LLIL_CONST,\
                                     LowLevelILOperation.LLIL_UNIMPL_MEM,\
                                     LowLevelILOperation.LLIL_SET_REG]:
                    # TODO
                if (il_inst.operation == LowLevelILOperation.LLIL_STORE):
                #yield il_inst.address
                    try:
            
                        yield self.bv.is_valid_offset(il_inst.operands[0].value), il_inst.address
                    except:
                        pass

    def scan_potential_pointers(self, func_addr):
        # Iterate over all instructions in each basic block
        fobj = self.bv.get_function_at(func_addr)
        for block in fobj.low_level_il:
            for target, instAddr in self.scan_potential_pointers_bb(block, fobj):
                yield target, instAddr

    def is_plausible_pointer(self, candidate_ptr):
        return self.bv.is_valid_offset(candidate_ptr)


    def find_section(self, addr):
        '''
            Function should find what segment/section $addr is in and return a tuple
            (StartAddress, Endaddress, Segment Name)
            Error: Return -1
        '''
        res = []
        for sec in self.bv.get_sections_at(addr):
            return ((sec.start, sec.start + sec.length, sec.name))
        return -1


    def highlight_instr(self, func_addr, instrAddr, color):
        fobj = self.bv.get_functions_containing(func_addr)[0]
        if color == "red":
            bn_color = HighlightStandardColor.RedHighlightColor
        elif color == "blue":
            bn_color = HighlightStandardColor.BlueHighlightColor
        elif color == "yellow":
            bn_color = HighlightStandardColor.YellowHighlightColor
        elif color == "orange":
            bn_color = HighlightStandardColor.OrangeHighlightColor
        else:
            raise (ValueError, "Unsupported color")
        fobj.set_user_instr_highlight(instrAddr, bn_color)

    def add_comment(self, func_addr, instrAddr, comment):
        fobj = self.bv.get_functions_containing(func_addr)[0]
        fobj.set_comment(instrAddr, "[ripr] " + comment)

    def display_info(self, info1, info2):
        self.bv.show_plain_text_report(info1, info2)

class radare2_engine(aengine):
    def get_data_symbols(self):
        for symbol in self.r2.cmdj("isj"):
            if symbol['type'] == "OBJECT":
                yield symbol['vaddr']


    def get_strings(self):
         for symbol in self.r2.cmdj("izj"):
            yield symbol['vaddr'], symbol['size']

    def get_refs_to(self, address):
        res = self.r2.cmd("axtj {}".format(hex(address)))
        if res is None or len(res) == 0:
            return
        res = json.loads(res)
        for ref in res:
            yield ref['from']

    def function_contains_addr(self, func_addr, testAddr):
        func = self.r2.cmdj("afij @{}".format(hex(func_addr)))
        func = func[0]
        return testAddr >= func['offset'] and testAddr < func['offset']+func['size']

    def __init__(self, r2):
        self.r2 = r2
        aengine.__init__(self)

    def read_bytes(self, address, size):
        bytes = []
        hexdump = self.r2.cmd("pc {} @ {}".format(size,hex(address)))
        for line in hexdump.split("\n"):
            if "0x" in line:
                for byte in line.split(","):
                    byte = byte.strip()
                    if len(byte) == 0:
                        continue
                    byte = int(byte, 16)
                    bytes.append(chr(byte))
        assert len(bytes) == size
        return ''.join(bytes)

    def get_arch(self):
        info = self.r2.cmdj("ifj")
        arch = info['bin']['arch']
        bits = info['bin']['bits']
        if arch == "x86" and bits == 32:
            return 'x86'
        elif arch == "x86" and bits == 64:
            return 'x64'
        else:
            raise (NotImplementedError, "Only tested witn x86 & x86_64")

    def get_function_bytes(self, address=None, name=None):
        if (address != None):
            funcInfo = self.r2.cmd("afij {}".format(hex(address)))
        elif (name != None):
            print ("[ripr] TODO")
            return
        else:
            print ("[ripr] No arguments supplied to get_function_bytes")
            return None

        if funcInfo.strip() == "":
            raise (ValueError, "Function not found at {}".format(address))
        funcInfo = json.loads(funcInfo, strict=False)

        if len(funcInfo) == 0:
            raise (ValueError, "Function not found at {}".format(address))
        print (funcInfo)
        offset = funcInfo[0]["offset"]
        size = funcInfo[0]["size"]
        bytes = self.read_bytes(offset, size)
        retdir = {offset: codeSlice(bytes, offset)}
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
        return self.r2.cmd("pa nop").decode('hex')

    def generate_invalid_access(self, address, arch, size=None):
        '''
            Generates an invalid memory access for use in function hooking.
            pad to size if applicable
        '''
        # TODO: Radare2 seems to assemble this to a rip-relative access?
        if arch in ['x86', 'x64']:
            if (size):
                opcodes = self.r2.cmd('pa mov al, [%s]' % address).decode('hex')
                nop = self.get_nop_opcode()
                if len(opcodes) >= size:
                    return opcodes
                return opcodes + nop * (size - len(opcodes))
            else:
                return self.r2.cmd('pa mov al, [%s]' % address).decode('hex')

    def get_imports(self):
        # Iterate through symbols and grab everything that starts with 'sym.'
        res = {}
        for sym in self.r2.cmdj("isj"):
            if sym['name'].startswith("imp."):
                res[sym['vaddr']] = sym['name'][4:]
        return res

    def branches_from_func(self, address, callCallback, branchCallback):
        func = self.r2.cmdj("pdfj @ {}".format(hex(address)))
        instructions = func['ops']
        for instr in instructions:
            if instr['type'] == 'call':
                callCallback(instr['jump'], instr['offset'])
            elif instr['type'] == 'cjmp' or instr['type'] == 'jmp':
                branchCallback(instr['jump'], instr['offset'])
            #TODO: Any other?

    def scan_potential_pointers(self, func_addr):
        # Leverage Radare2 automatic pointer detection
        func = self.r2.cmdj("pdfj @ {}".format(hex(func_addr)))
        res = []
        for line in func['ops']:
            if 'ptr' in line:
                yield line['ptr'], line['offset']

    def is_plausible_pointer(self, candidate_ptr):
        # A manual scan of all sections
        for section in self.r2.cmdj("Sj"):
            if candidate_ptr >= section['vaddr'] and \
                candidate_ptr < section['vaddr'] + section['vsize']:
                return True
        return False

    def find_section(self, addr):
        '''
            Function should find what segment/section $addr is in and return a tuple
            (StartAddress, Endaddress, Segment Name)
            Error: Return -1
        '''
        # A manual scan of all sections
        res = []
        for section in self.r2.cmdj("Sj"):
            if addr >= section['vaddr'] and \
                addr < section['vaddr'] + section['vsize']:
                return (
                    section['vaddr'],
                    section['vaddr'] + section['vsize'],
                    section['name'])

        return -1

    def get_instruction_length(self, address):
        return self.r2.cmdj("pdj 1 @{}".format(hex(address)))[0]['size']

    def highlight_instr(self, func_addr, instrAddr, color):
        # No highlighting yet
        pass

    def add_comment(self, func_addr, instrAddr, comment):
        if not re.compile("^[a-z0-9 !\\-\\_]+$", re.IGNORECASE).match(comment):
            # Don't send arbitrary contents to radare pipe
            print ("Ignoring malformed comment: {}".format(comment))
        else:
            self.r2.cmd("CC [ripr] {} @{}".format(comment, hex(instrAddr)))

