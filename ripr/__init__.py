import sys
if (sys.platform == 'win32'):
    sys.path.append("C:\\Python27\\lib\\site-packages\\PyQt5")
try:
    from binaryninja import *

    # ripr imports
    from analysis_engine import *
    from codegen import *
    from packager import *
    import gui

    ui = gui.riprWidget()
    def packageFunction(view, fobj):
        engine = get_engine(view, fobj)
        pkg = Packager(isFunc=True, address=fobj.start, engine=engine, ui=ui)
        pkg.package_function()

    def packageRegion(view, start, length):
        print "[ripr] Packaging 0x%x - 0x%x" % (start, start+length)
        engine = get_engine(view)
        pkg = Packager(isFunc=False, address=start, engine=engine, length=length, ui=ui)
        pkg.package_region()


    PluginCommand.register_for_function("[ripr] Package Function", "Package Function within Unicorn", packageFunction)
except ImportError:
    pass
