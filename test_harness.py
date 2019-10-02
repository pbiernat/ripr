'''
This file is analogous to packager, but with user-interaction components stripped out. This 
makes it easier to write automated tests.
'''

from .codegen import *
from .analysis_engine import aengine as ae
from .dependency import depScanner
from .conScan import convenienceScanner

### Global for listing all chunks of code for which we have tried to create a python wrapper.
emuchunks = {}
    
# List of basic block chunks to package for BB mode
bbChunks = []
class t_Packager(object):
    '''
        Packager does the work of getting a codegen object
        the information it needs for creating a suitable emulation environment.
    '''
    def __init__(self, isFunc, address, engine, ui = None, length=None):  
        self.isFunc = isFunc
        self.address = address
        self.length = length
        self.engine = engine
        self.ui = ui

        # List of Contiguous code we're interested in
        self.targetCode = []
        
        self.codeobj = genwrapper('', isFunc)
        self.arch = self.engine.get_arch()
        self.codeobj.setArch(self.arch)

        self.impCallStrategy = None
        self.dataStrategy = None
        self.resolve_arguments = None

        self.codeobj.startaddr = int(self.address)
        if (self.length != None):
            self.codeobj.codelen = length

    def convenience_passes(self):
        '''
            This function is a wrapper for determining which convenience features can 
            be enabled during code generation.
        '''
        c = convenienceScanner(self.engine)
        if (self.isFunc == True and self.codeobj.arch in ['x64', 'x86', 'arm']):
            self.codeobj.conPass['ret'] = True

        args = None
        if (self.isFunc):
            if (self.resolve_arguments == True):
                args = c.argIdent(self.address, self.isFunc)
                if args:
                    self.codeobj.conPass['args'] = args

        if not self.isFunc:
            self.codeobj.conPass['unset_vars'] = c.uninit_vars(bbChunks) 

    def minimal_package_function(self, address=None):
        '''
            Adds basic information to CodeGen when packaging a function.
        '''
        if (address == None):
            address = self.address
        # Get the code to be emulated
        localCode = self.engine.get_function_bytes(address=address)
        if (localCode == None):
            self.ui.msgBox("[ripr] Couldn't get function binary view. Maybe code arch is thumb2?")
            return False
        # Add each contiguous chunk of code to codeobj and make sure
        # it will be mapped.
        for startAddr in list(localCode.keys()):
            self.codeobj.add_mmap(startAddr)
        
        self.targetCode.append(localCode)
        return True
        
    def minimal_package_region(self):
        targetCode = self.engine.get_region_bytes(address=self.address)
        self.codeobj.add_data(targetCode[0], targetCode[1])
        self.codeobj.add_mmap(targetCode[0])

    def minimal_package_bb(self, address=None):
        if (address == None):
            address = self.address
        targetCode = self.engine.get_basic_block_bytes(address)
        self.engine.mark_gathered_basic_block(address)

        bbChunks.append(targetCode)
        

    def package_function(self, cname):
        '''
            This method handles filling in as much relevant information as possible into our current instance of codeobj
            about the function to be emulated. It is a high-level encapsulation of multipe packaging and analysis methods.
        '''
        self.codeobj.name = cname

        # Get the bare minimum required information.
        if (self.minimal_package_function()==False):
            return

        # Try to find dependencies of our code.
        self.resolve_dependencies()

        # Figure out if we can add any convenience methods to our generated code
        self.convenience_passes()

        # Add gathered information to the code object.
        self.update_codeobj()

        # Add the codeobj to the global storage for listing in the UI (if available)
        emuchunks[self.codeobj.name] = self.codeobj
        self.ui.update_table(emuchunks)

        # Generate what we currently have and show the results
        self.codeobj.generate_class()

    def package_bb(self):
        '''
            This method adds an entry to bbChunks, which can be used later to 
            generate a package containing only user-specified basic blocks.
        '''
        self.minimal_package_bb()


    def generate_bb_code(self, cname):
        global bbChunks
        if len(bbChunks) == 0:
            self.ui.msgBox("Basic Block package list is empty!")
            return
        self.codeobj.name = cname
        if not self.codeobj.name:
            return

        # Set starting address to first basic block selected
        self.codeobj.startaddr = list(bbChunks[0].keys())[0]

        self.targetCode = bbChunks

        self.resolve_dependencies()

        self.convenience_passes()

        self.update_codeobj()
        
        # Clean up our modifications
        self.cleanup_basic_blocks()
        bbChunks = []

        self.codeobj.generate_class()
        self.engine.display_info("Generated Code: %s" % self.codeobj.name, self.codeobj.final)

        self.ui.save_file(self.codeobj)
    
    def cleanup_basic_blocks(self):
        global bbChunks
        for bb in bbChunks:
            self.engine.clean_gathered_basic_block(list(bb.keys())[0])
        

    def package_region(self):
        '''
            This method handles filling in as much information as possible about the target region to be emulated.
        '''
        self.minimal_package_region()

        self.resolve_dependencies()

        self.convenience_passes()

    def _find_code_unit(self, faddr):
        for found_code in self.targetCode:
            for addr in found_code:
                codeLen = len(found_code[addr].code_bytes)
                if ( (faddr >= addr) and (faddr <= addr + codeLen)):
                    return found_code[addr]

    def _nop_impFunc(self, impCalls):
        for impCall in impCalls:
            print ("[ripr] Nopping out Imported Call: 0x%x" % (impCall.address))
            cSlice = self._find_code_unit(impCall.address)

            codeLen = len(cSlice.code_bytes)
            nop = self.engine.get_nop_opcode()
            
            if (impCall.inst_len % len(nop) != 0):
                print ("[ripr] Cannot NOP out instruction...")
                return

            # Create string of NOP opcodes and calculate where to place it
            nopStr = nop * (impCall.inst_len / len(nop))
            first = impCall.address - cSlice.address
            second = first + len(nopStr)

            newCode = cSlice.code_bytes[0:first] + nopStr + cSlice.code_bytes[second:]
            cSlice.code_bytes = newCode


    def update_codeobj(self):
        # targetCode[0] corresponds to the dict of code units for the original function
        # in the case of others being automatically mapped as dependencies
        
        localCode = self.targetCode[0]
        print (self.targetCode)
        self.codeobj.codelen = sum([len(localCode[x].code_bytes) for x in list(localCode.keys())])
        for found_code in self.targetCode:
            for addr in found_code:
                self.codeobj.add_code(found_code[addr])


    def resolve_imported_calls(self, resolv):
        if self.impCallStrategy == 'nop':
            self._nop_impFunc(resolv.impCalls)
        elif self.impCallStrategy == 'hook':
            self.codeobj.impCallTargets += resolv.impCalls
        else:
            return

    def map_dependent_pages(self, dataRefs):
        pagesize = self.engine.get_page_size()
        pages = []
        
        for ref in dataRefs:
            pageaddr = (ref.address & ~(pagesize - 1))
            pages.append(pageaddr)

        pages = set(pages)
        for page in pages:
            self.codeobj.add_data(self.engine.get_page_bytes(page), page)
            self.codeobj.add_mmap(page)

    def map_dependent_sections(self, dataRefs):
        '''
            Map any sections the target code touches.
        '''
        print ("Mapping Sections")
        pagesize = self.engine.get_page_size()
        secs = []
        
        for ref in dataRefs:
            section=self.engine.find_section(ref.address)
            if section!=-1:
                secs += [section]

        for sec_start, sec_end, sec_name in secs:
            self.codeobj.add_data(self.engine.read_bytes(sec_start, sec_end - sec_start), sec_start)
            self.codeobj.add_mmap(sec_start)

    def map_minimal_data(self, dataRefs):
        '''
            Attempt to only map the exact data the target code uses.
        '''
        pass

    def resolve_data_dependencies(self, dataRefs):
        '''
            This function handles finding data that needs to get mapped.
        '''
        if (self.dataStrategy == "section"):
            self.map_dependent_sections(dataRefs)
        else:
            self.map_dependent_pages(dataRefs)

    def resolve_codeRefs(self, coderefs):
        for ref in coderefs:
            print ("Found CodeRef: %x::%s" % (ref.address, ref.type))
            if (ref.type == 'call'):
                if (self.minimal_package_function(address=ref.address)==False):
                    continue
                self.resolve_dependencies(address=ref.address, isFunc=True)

    def resolve_dependencies(self, address=None, isFunc=None):
        '''
            This method is a high-level wrapper for finding data our target code depends on.
        '''
        resolv = depScanner(self.engine, self.codeobj) 
        if (address == None):
            address = self.address 

        if (isFunc == None):
            isFunc = self.isFunc

        print ("Resolving Dependencies for %x" % address)
        if isFunc:
            coderefs = resolv.branchScan(address, self.isFunc)
            datarefs = resolv.dataScan(address)
        else:
            datarefs = resolv.dataScan(address)
            coderefs = []
            for bb in bbChunks:
                coderefs += resolv.branchScan(list(bb.keys())[0], self.isFunc) 

        if (resolv.impCalls != []):
            self.resolve_imported_calls(resolv) 

        if (coderefs != []):
            if (self.ui.yes_no_box("Target code may depend on outside code, attempt to map automatically?") == True):
                print ("[ripr] Performing analysis on code dependencies...")
                self.resolve_codeRefs(coderefs)
            else:
                pass

        if (resolv.dataRefs != []):
            # Try to map these automatically
            print ("[ripr] Found these potential Data References")
            for ref in resolv.dataRefs:
                print ("Data Referenced: 0x%x" % (ref.address))
            self.resolve_data_dependencies(resolv.dataRefs)
            pass


