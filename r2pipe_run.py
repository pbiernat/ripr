import sys

# ripr imports
from analysis_engine import *
from codegen import *
from packager import *
import cli_ui

def packageFunction(addr):
    print "[ripr] Packaging function {}".format(hex(addr))
    engine = get_engine(addr)
    ui = cli_ui.cli_ui()
    pkg = Packager(isFunc=True, address=addr, engine=engine, ui=ui)
    pkg.package_function()

addr = int(sys.argv[1], 16)
packageFunction(addr)
