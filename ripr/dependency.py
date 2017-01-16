'''
    Code in this file deals with finding data and/or other code that must be 
    included in the emulation environment for the target code to be able to run
    properly.
'''

import analysis_engine as ae
from binaryninja import *

### TODO REWORK THIS INTO AN ABSTRACTED MODEL SIMILAR TO ANALYSIS ENGINE ###
class ImportedCall(object):
    '''
        Convenience class for storing information about imported Calls.
    '''
    def __init__(self, address, instlen, target, symname):
        self.address = address
        self.inst_len = instlen
        self.target = target
        self.symbol = symname

class riprDataRef(object):
    '''
        Convenience class for storing information on data references we find.
    '''
    def __init__(self, address, length, _type):
        self.address = address
        self.length = length
        self._type = _type

class riprCodeRef(object):
    def __init__(self, address, _type):
        self.address = address
        self.type = _type

class depScanner(object):
    def __init__(self, engine, codeobj):
        self.engine = engine
        self.codeobj = codeobj

        self.impCalls = []
        self.dataRefs = []
        self.codeRefs = []
        
        self.imports = {self.engine.bv.symbols[sym].address : self.engine.bv.symbols[sym] for sym in self.engine.bv.symbols if self.engine.bv.symbols[sym].type == 'ImportedFunctionSymbol'}

    def _mark_imported_call(self, fobj, address, target):
        '''
            Create an ImportedCall object for possible later use in "python-hooking"
            Note: We /do/ want duplicates (multiple ImportedCall objects for "puts" for example)
            as we map expected return addresses to our hooked functions.
        '''
        fobj.set_user_instr_highlight(self.engine.bv.arch, address, core.RedHighlightColor)
        fobj.set_comment(address, "[ripr] Imported Call !!")

        symname = str(target)
        if target in self.imports.keys():
            symname = self.imports[target]
        
        icall = ImportedCall(address, self.engine.bv.get_instruction_length(self.engine.bv.arch, address), target, symname)
        self.impCalls.append(icall) 

    def _mark_additional_branch(self, fobj, address, destination, _type): 
        ref = riprCodeRef(destination, _type)
        fobj.set_user_instr_highlight(self.engine.bv.arch, address, core.BlueHighlightColor)
        
        self.codeRefs.append(ref)

    def _mark_identified_data(self, fobj, address):
        fobj.set_user_instr_highlight(self.engine.bv.arch, address, core.YellowHighlightColor)
    
    def branchScan(self, address):
        '''
            Function is responsible for mapping calls and jumps
            that are outside the current selection's bounds, if possible.
        '''
        print "[ripr] Inside branchScan"
        ret = []

        
        fobj = self.engine.bv.get_function_at(self.engine.bv.platform, address)
        for block in fobj.low_level_il:
            for il_inst in block:
                print il_inst
                if (il_inst.operation == core.LLIL_CALL):
                    #core.LLIL_JUMP, core.LLIL_JUMP_TO, core.LLIL_GOTO]):
                    if (il_inst.dest.value in self.imports):
                        print "[ripr] Found imported Call target..."
                        self._mark_imported_call(fobj, il_inst.address, il_inst.dest.value)
                    
                    elif  (self.codeobj.data_saved(il_inst.dest.value) == False):
                        print "[ripr] Found LLIL CALL instruction"
                        print "[ripr] IL_INST Dest:"
                        self._mark_additional_branch(fobj, il_inst.address, il_inst.dest.value, "call")
                    else:
                        print "[ripr] Target address already mapped"

                # Check Jump targets
                elif (il_inst.operation in [core.LLIL_JUMP, core.LLIL_JUMP_TO, core.LLIL_GOTO]):
                    print "[ripr] JUMP TARGET: %s" % (str(il_inst.dest))
                    print dir(il_inst.dest)
                else:
                    pass
        return self.codeRefs

    def _find_stringRefs(self, fobj):
        '''
            Look for strings that are referenced in the selected code.
        '''
        ret = []
        for st in self.engine.bv.strings:
            for ref in self.engine.bv.get_code_refs(st.start, st.length):
                print ref.address
                if (fobj.get_basic_block_at(fobj.arch, ref.address) != None):
                    print "[ripr] Found string reference: 0x%x" % (ref.address)
                    self._mark_identified_data(fobj, ref.address)
                    dref = riprDataRef(st.start, st.length, 'str')
                    self.dataRefs.append(dref)
        return ret
        
    def _find_symbolRefs(self, fobj):
        '''
            Look for data symbols that are referenced in the selected code.
        '''
        ret = []
        symbols = {sym: self.engine.bv.symbols[sym] for sym in self.engine.bv.symbols if self.engine.bv.symbols[sym].type == 'DataSymbol'}

        for sym in symbols:
            for ref in self.engine.bv.get_code_refs(symbols[sym].address):
                if (fobj.get_basic_block_at(fobj.arch, ref.address) != None):
                    print "[ripr] Found Symbol Reference: 0x%x references 0x%x" % (ref.address, symbols[sym].address)
                    self._mark_identified_data(fobj, ref.address)
                    dref = riprDataRef(symbols[sym].address, -1, 'sym')
                    self.dataRefs.append(dref)
                    ret.append(symbols[sym].address)
        return ret

    def _simpleDataScan(self, fobj):
        ret = []
        ret += self._find_stringRefs(fobj)
        ret += self._find_symbolRefs(fobj)
        return ret

    def dataScan(self, address):
        '''
            Function is responsible for finding data the target code
            needs in order to run correctly.
        '''
        print "[ripr] Inside dataScan"
        ret = []
        # Get a Function object at this address
        fobj = self.engine.bv.get_function_at(self.engine.bv.platform, address)
        
        # Find the low-hanging fruit
        ret += self._simpleDataScan(fobj)

        # Iterate over all instructions in each basic block
        for block in fobj.low_level_il:
            for il_inst in block:
                constants = fobj.get_constants_referenced_by(self.engine.bv.arch, il_inst.address)
                # Check if constant is a likely pointer
                for const in constants:
                    if self.engine.bv.is_valid_offset(const.value):
                        print "Found Potential Pointer: %s" % (const)
                        self._mark_identified_data(fobj, il_inst.address)
                        dref = riprDataRef(const.value, -1, 'ptr')
                        self.dataRefs.append(dref)
                        ret.append(const.value)
                # Memory things 
                if (il_inst.operation in [core.LLIL_LOAD, core.LLIL_STORE, core.LLIL_CONST, core.LLIL_UNIMPL_MEM, core.LLIL_SET_REG]):
                    print "[ripr] Found memory based instruction"
                    print "%s ::> %s" % (il_inst, il_inst.operation_name)
                    print il_inst.operands
                    if (il_inst.operation == core.LLIL_STORE):
                        try:
                            if self.engine.bv.is_valid_offset(il_inst.operands[0].value):
                                val = il_inst.operands[0].value
                                print "Need to mmap; %x" % val
                                self._mark_identified_data(fobj, il_inst.address)
                                dref = riprDataRef(val, -1, 'ptr')
                                self.dataRefs.append(dref)
                                ret.append(val)
                        except:
                            pass

            return set(ret)

class convenienceScanner(object):
    
    def __init__(self, fobj, codeobj):
        self.fobj = None
        pass

    def argIdent(self):

        pass




