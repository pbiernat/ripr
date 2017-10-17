from codegen import *
import analysis_engine as ae
import dependency as dep

### Global for listing all chunks of code for which we have tried to create a python wrapper.
emuchunks = {}

# List of basic block chunks to package for BB mode
bbChunks = []
class Packager(object):
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
        self.ui.emuchunks = emuchunks

        # List of Contiguous code we're interested in
        self.targetCode = []
        
        self.codeobj = genwrapper('', isFunc)
        self.arch = self.engine.get_arch()
        self.codeobj.arch = self.arch

        self.impCallStrategy = None
        self.dataStrategy = None

        self.codeobj.startaddr = int(self.address)
        if (self.length != None):
            self.codeobj.codelen = length

    def convenience_passes(self):
        '''
            This function is a wrapper for determining which convenience features can 
            be enabled during code generation.
        '''
        if (self.isFunc == True and self.codeobj.arch in ['x64', 'x86', 'arm']):
            self.codeobj.conPass['ret'] = True

    def minimal_package_function(self, address=None):
        '''
            Adds basic information to CodeGen when packaging a function.
        '''
        if (address == None):
            address = self.address
        # Get the code to be emulated
        localCode = self.engine.get_function_bytes(address=address)

        # Add each contiguous chunk of code to codeobj and make sure
        # it will be mapped.
        for startAddr in localCode.keys():
            self.codeobj.add_mmap(startAddr)
        
        self.targetCode.append(localCode)

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
        

    def package_function(self):
        '''
            This method handles filling in as much relevant information as possible into our current instance of codeobj
            about the function to be emulated. It is a high-level encapsulation of multipe packaging and analysis methods.
        '''
        self.codeobj.name = self.ui.text_input_box("Enter Class Name")
        # Get the bare minimum required information.
        self.minimal_package_function()

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
        self.engine.display_info("Generated Code: %s" % self.codeobj.name, self.codeobj.final)
        if not self.ui.qtAvailable:
            self.ui.save_file(self.codeobj) 

    def package_bb(self):
        '''
            This method adds an entry to bbChunks, which can be used later to 
            generate a package containing only user-specified basic blocks.
        '''
        self.minimal_package_bb()


    def generate_bb_code(self):
        global bbChunks
        if len(bbChunks) == 0:
            return
        self.codeobj.name = self.ui.text_input_box("Enter Class Name")
        # Set starting address to first basic block selected
        self.codeobj.startaddr = bbChunks[0].keys()[0]

        self.targetCode = bbChunks

        self.resolve_dependencies()

        self.update_codeobj()
        
        # Clean up our modifications
        self.cleanup_basic_blocks()
        bbChunks = []

        self.codeobj.generate_class()
        self.engine.display_info("Generated Code: %s" % self.codeobj.name, self.codeobj.final)
    
    def cleanup_basic_blocks(self):
        global bbChunks
        for bb in bbChunks:
            self.engine.clean_gathered_basic_block(bb.keys()[0])
        

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
            print "[ripr] Nopping out Imported Call: 0x%x" % (impCall.address)
            cSlice = self._find_code_unit(impCall.address)

            codeLen = len(cSlice.code_bytes)
            nop = self.engine.get_nop_opcode()
            
            if (impCall.inst_len % len(nop) != 0):
                print "[ripr] Cannot NOP out instruction..."
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
        print self.targetCode
        self.codeobj.codelen = sum([len(localCode[x].code_bytes) for x in localCode.keys()])
        for found_code in self.targetCode:
            for addr in found_code:
                self.codeobj.add_code(found_code[addr])


    def resolve_imported_calls(self, resolv):
        print "[ripr] Selection includes calls to imported Functions!"
        if self.impCallStrategy == None:
            self.impCallStrategy = self.ui.impCallsOptions()
        
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
        print "Mapping Sections"
        pagesize = self.engine.get_page_size()
        secs = []
        for ref in dataRefs: 
            sections = [self.engine.find_section(ref.address)]
            secs += sections
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
        if (self.dataStrategy == None):
            if (self.ui.yes_no_box("Use Section-Marking Mode for data dependencies (default; yes)")):
                self.dataStrategy = "section"
            else:
                self.dataStrategy = "page"
        
        if (self.dataStrategy == "section"):
            self.map_dependent_sections(dataRefs)
        else:
            self.map_dependent_pages(dataRefs)

    def resolve_codeRefs(self, coderefs):
        for ref in coderefs:
            print "Found CodeRef: %x::%s" % (ref.address, ref.type)
            if (ref.type == 'call'):
                self.minimal_package_function(address=ref.address)
                self.resolve_dependencies(address=ref.address)

    def resolve_dependencies(self, address=None):
        '''
            This method is a high-level wrapper for finding data our target code depends on.
        '''
        resolv = dep.depScanner(self.engine, self.codeobj) 
        if (address == None):
            address = self.address 

        print "Resolving Dependencies for %x" % address
        if self.isFunc:
            coderefs = resolv.branchScan(address, self.isFunc)
            datarefs = resolv.dataScan(address)
        else:
            datarefs = resolv.dataScan(address)
            coderefs = []
            for bb in bbChunks:
                coderefs += resolv.branchScan(bb.keys()[0], self.isFunc) 

        if (resolv.impCalls != []):
            self.resolve_imported_calls(resolv) 

        if (coderefs != []):
            if (self.ui.yes_no_box("Target code may depend on outside code, attempt to map automatically?") == True):
                print "[ripr] Performing analysis on code dependencies..."
                self.resolve_codeRefs(coderefs)
            else:
                pass

        if (resolv.dataRefs != []):
            # Try to map these automatically
            print "[ripr] Found these potential Data References"
            for ref in resolv.dataRefs:
                print "Data Referenced: 0x%x" % (ref.address)
            self.resolve_data_dependencies(resolv.dataRefs)
            pass
