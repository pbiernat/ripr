import sys

if (sys.platform == 'win32'):
    if sys.version_info[0] >= 3:
        sys.path.append("C:\\Python37\\lib\\site-packages\\PyQt5")
    else:
        sys.path.append("C:\\Python27\\lib\\site-packages\\PyQt5")
try:
    from binaryninja import *
   
    # Do not try to load if this is hit from "headless"/python api
    #if core_product_type == '':
    #    raise ImportError

    # ripr imports
    from .analysis_engine import *
    from .codegen import *
    from .packager import *
    from .gui import *


    ui = gui.riprWidget()
    def packageFunction(view, fobj):
        engine = get_engine(view, fobj)
        pkg = Packager(isFunc=True, address=fobj.start, engine=engine, ui=ui)
        pkg.package_function()

    def packageRegion(view, start, length):
        print ("[ripr] Packaging 0x%x - 0x%x" % (start, start+length))
        engine = get_engine(view)
        pkg = Packager(isFunc=False, address=start, engine=engine, length=length, ui=ui)
        pkg.package_region()

    def packageBasicBlock(view, addr):
        print ("[ripr] Adding Basic Block containing %x " % addr)
        engine = get_engine(view)
        pkg = Packager(isFunc=False, address=addr, engine=engine, ui=ui)
        pkg.package_bb()

    def generate_basicBlocks(view, fobj):
        print ("[ripr] Generating code from currently selected basic blocks")
        engine = get_engine(view)
        pkg = Packager(isFunc=False, address=fobj.start, engine=engine, ui=ui)
        pkg.generate_bb_code()

    PluginCommand.register_for_function("[ripr] Package Function", "Package Function within Unicorn", packageFunction)
    
    PluginCommand.register_for_address("[ripr] Package BasicBlock", "Package Function within Unicorn", packageBasicBlock)
    
    PluginCommand.register_for_function("[ripr] Generate Selected BBs", "Package Function within Unicorn", generate_basicBlocks)

except ImportError as e:
    raise e
    pass
