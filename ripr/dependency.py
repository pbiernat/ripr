'''
    Code in this file deals with finding data and/or other code that must be 
    included in the emulation environment for the target code to be able to run
    properly.
'''

import analysis_engine as ae

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
        
        self.imports = self.engine.get_imports()

    def _mark_imported_call(self, func_addr, address, target):
        '''
            Create an ImportedCall object for possible later use in "python-hooking"
            Note: We /do/ want duplicates (multiple ImportedCall objects for "puts" for example)
            as we map expected return addresses to our hooked functions.
        '''
        self.engine.highlight_instr(func_addr, address, "red")
        self.engine.add_comment(func_addr, address, "Imported Call !!")

        symname = str(target)
        if target in self.imports.keys():
            symname = self.imports[target]
        
        icall = ImportedCall(address, self.engine.get_instruction_length(address), target, symname)
        self.impCalls.append(icall) 

    def _mark_additional_branch(self, func_addr, address, destination, _type):
        ref = riprCodeRef(destination, _type)
        self.engine.highlight_instr(func_addr, address, "blue")
        self.codeRefs.append(ref)

    def _mark_identified_data(self, func_addr, ref_addr):
        self.engine.highlight_instr(func_addr, ref_addr, "yellow")
    
    def branchScan(self, address, isFunc=True):
        '''
            Function is responsible for mapping calls and jumps
            that are outside the current selection's bounds, if possible.
        '''
        print "[ripr] Inside branchScan"
        def callCallback(dest, instr_addr):
            if type(dest) != int:
                try:
                    dest = dest.value
                except:
                    return
            if (dest in self.imports):
                print "[ripr] Found imported Call target..."
                self._mark_imported_call(address, instr_addr, dest)

            elif  (self.codeobj.data_saved(dest) == False):
                print "[ripr] Found LLIL CALL instruction"
                self._mark_additional_branch(address, instr_addr, dest, "call")
            else:
                print "[ripr] Target address already mapped"

        def jumpCallback(dest, instr_addr):
            print "[ripr] JUMP TARGET: %s" % (dest)

        if isFunc:
            self.engine.branches_from_func(address, callCallback, jumpCallback)
        else:
            ibb = self.engine.find_llil_block_from_addr(address)
            print "FOUND BB FROM ADDR::"
            print ibb
            self.engine.branches_from_block(ibb, callCallback, jumpCallback)
        return self.codeRefs

    def _find_stringRefs(self, address):
        '''
            Look for strings that are referenced in the selected code.
        '''

        ret = []
        for stringStart,stringLength in self.engine.get_strings():
            for refAddress  in self.engine.get_refs_to(stringStart): # Ignored the length
                if (self.engine.function_contains_addr(address, refAddress)):
                    print "[ripr] Found string reference: 0x%x" % (refAddress)
                    self._mark_identified_data(address, refAddress)
                    dref = riprDataRef(stringStart, stringLength, 'str')
                    self.dataRefs.append(dref)
        return ret
        
    def _find_symbolRefs(self, address):
        '''
            Look for data symbols that are referenced in the selected code.
        '''
        ret = []
        symbols = self.engine.get_data_symbols()
        for symStart in symbols:
            for refAddress in self.engine.get_refs_to(symStart):
                if self.engine.function_contains_addr(address, refAddress):
                    print "[ripr] Found Symbol Reference: 0x%x references 0x%x" % (refAddress, symStart)
                    self._mark_identified_data(address, refAddress)
                    dref = riprDataRef(symStart, -1, 'sym')
                    self.dataRefs.append(dref)
                    ret.append(symStart)
        return ret

    def _simpleDataScan(self, address):
        ret = []
        ret += self._find_stringRefs(address)
        ret += self._find_symbolRefs(address)
        return ret

    def dataScan(self, address):
        '''
            Function is responsible for finding data the target code
            needs in order to run correctly.
        '''
        print "[ripr] Inside dataScan"
        ret = []
        
        # Find the low-hanging fruit
        ret += self._simpleDataScan(address)

        # Iterate over all instructions for potential pointers
        for target, instrAddr in self.engine.scan_potential_pointers(address):
            if self.engine.is_plausible_pointer(target):
                print "Found Potential Pointer: %s instaddr %s" % (hex(target), hex(instrAddr))
                self._mark_identified_data(address, instrAddr)
                dref = riprDataRef(target, -1, 'ptr')
                self.dataRefs.append(dref)
                ret.append(target)

        return set(ret)

class ilVar(object):
    def __hash__(self):
        return self.var.__hash__()

    def __eq__(self, other):
        return self.var == other.var

    def __init__(self, var, mil):
        self.var = var
        self.mil = mil

class convenienceScanner(object):
    def __init__(self, engine):
        self.engine = engine

    def argIdent(self, addr, isFunc):
        fobj = self.engine.bv.get_functions_containing(addr)
        if len(fobj) > 1:
            return None
        fobj = fobj[0]
        if (isFunc):
            ftype = fobj.function_type
            return ftype.parameters
            
    def uninit_vars(self, bbs):
        for bb in bbs:
            mlb = self.engine.find_mlil_block_from_addr(bb.keys()[0]) 
            if mlb == None:
                continue
            set_vars = []
            unset_vars = []
            for il in mlb:
                for v in il.vars_written:
                    set_vars.append(v)    
                for v in il.vars_read:
                    if v not in set_vars:
                        unset_vars.append(ilVar(v, il))

            unset_vars = set(unset_vars)
            for uVar in unset_vars:
                self.engine.highlight_instr(bb.keys()[0], uVar.mil.address, "blue")     
