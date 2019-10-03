import unittest
import subprocess
import sys,os

print("Trying to import ripr...")

from ripr import test_harness
from ripr import gui
from ripr import analysis_engine

import binaryninja

class x64_impTest(unittest.TestCase):
    def test(self):
        print ("Starting Test")
        dname = os.path.dirname(os.path.abspath(__file__))
        bv = binaryninja.BinaryViewType["ELF"].open(dname+"/../sample/impCall/x64_impCall.bin")
        bv.update_analysis_and_wait()
        
        target = 0
        for f in bv.functions:
            if f.name == "main":
                target = f.start

        print ("Finished Loading Binary")
        engine = analysis_engine.bn_engine(bv)
        ui_ = gui.riprWidget()

        p = test_harness.t_Packager(True, target, engine, ui=ui_)
        p.impCallStrategy = 'hook'
        p.dataStrategy = 'section'
        p.resolve_arguments = True
        p.package_function("x64_test")
        
        if not os.path.exists('/tmp/riprtest'):
            os.makedirs('/tmp/riprtest/')

        t = open('/tmp/riprtest/x64_impCall.py', 'w+')
        t.write(p.codeobj.final)
        t.close()

        testProc = subprocess.check_output(['python', '/tmp/riprtest/x64_impCall.py'])
        self.assertIn('1337', testProc) 

class x64_pageTest(unittest.TestCase):
    def test(self):
        print ("Starting Test")
        dname = os.path.dirname(os.path.abspath(__file__))
        bv = binaryninja.BinaryViewType["ELF"].open(dname+"/../sample/impCall/x64_impCall.bin")
        bv.update_analysis_and_wait()
        
        target = 0
        for f in bv.functions:
            if f.name == "main":
                target = f.start

        print ("Finished Loading Binary")
        engine = analysis_engine.bn_engine(bv)
        ui_ = gui.riprWidget()

        p = test_harness.t_Packager(True, target, engine, ui=ui_)
        p.impCallStrategy = 'hook'
        p.dataStrategy = 'page'
        p.resolve_arguments = True
        p.package_function("x64_test")
        
        if not os.path.exists('/tmp/riprtest'):
            os.makedirs('/tmp/riprtest/')

        t = open('/tmp/riprtest/x64_pageimpCall.py', 'w+')
        t.write(p.codeobj.final)
        t.close()

        testProc = subprocess.check_output(['python', '/tmp/riprtest/x64_pageimpCall.py'])
        self.assertIn('1337', testProc) 

class x64_nopTest(unittest.TestCase):
    def test(self):
        print ("Starting Test")
        dname = os.path.dirname(os.path.abspath(__file__))
        bv = binaryninja.BinaryViewType["ELF"].open(dname+"/../sample/impCall/x64_impCall.bin")
        bv.update_analysis_and_wait()
        
        target = 0
        for f in bv.functions:
            if f.name == "main":
                target = f.start

        print ("Finished Loading Binary")
        engine = analysis_engine.bn_engine(bv)
        ui_ = gui.riprWidget()

        p = test_harness.t_Packager(True, target, engine, ui=ui_)
        p.impCallStrategy = 'nop'
        p.dataStrategy = 'section'
        p.resolve_arguments = True
        p.package_function("x64_test")
        
        if not os.path.exists('/tmp/riprtest'):
            os.makedirs('/tmp/riprtest/')

        t = open('/tmp/riprtest/x64nop_impCall.py', 'w+')
        t.write(p.codeobj.final)
        t.close()

        testProc = subprocess.check_output(['python', '/tmp/riprtest/x64nop_impCall.py'])
        self.assertIn('1337', testProc) 

class x86Test(unittest.TestCase):
    def test(self):
        print ("Starting Test")
        dname = os.path.dirname(os.path.abspath(__file__))
        bv = binaryninja.BinaryViewType["ELF"].open(dname+"/../sample/impCall/x86_impCall.bin")
        bv.update_analysis_and_wait()
        
        target = 0
        for f in bv.functions:
            if f.name == "main":
                target = f.start

        print ("Finished Loading Binary")
        engine = analysis_engine.bn_engine(bv)
        ui_ = gui.riprWidget()

        p = test_harness.t_Packager(True, target, engine, ui=ui_)
        p.impCallStrategy = 'hook'
        p.dataStrategy = 'section'
        p.resolve_arguments = True
        p.package_function("x64_test")
        
        if not os.path.exists('/tmp/riprtest'):
            os.makedirs('/tmp/riprtest/')

        t = open('/tmp/riprtest/x86_impCall.py', 'w+')
        t.write(p.codeobj.final)
        t.close()

        testProc = subprocess.check_output(['python', '/tmp/riprtest/x86_impCall.py'])
        self.assertIn('1337', testProc) 

class x86_nopTest(unittest.TestCase):
    def test(self):
        print ("Starting Test")
        dname = os.path.dirname(os.path.abspath(__file__))
        bv = binaryninja.BinaryViewType["ELF"].open(dname+"/../sample/impCall/x86_impCall.bin")
        bv.update_analysis_and_wait()
        
        target = 0
        for f in bv.functions:
            if f.name == "main":
                target = f.start

        print ("Finished Loading Binary")
        engine = analysis_engine.bn_engine(bv)
        ui_ = gui.riprWidget()

        p = test_harness.t_Packager(True, target, engine, ui=ui_)
        p.impCallStrategy = 'nop'
        p.dataStrategy = 'section'
        p.resolve_arguments = True
        p.package_function("x64_test")
        
        if not os.path.exists('/tmp/riprtest'):
            os.makedirs('/tmp/riprtest/')

        t = open('/tmp/riprtest/x86nop_impCall.py', 'w+')
        t.write(p.codeobj.final)
        t.close()

        testProc = subprocess.check_output(['python', '/tmp/riprtest/x86nop_impCall.py'])
        self.assertIn('1337', testProc) 

class x86_pageTest(unittest.TestCase):
    def test(self):
        print ("Starting Test")
        dname = os.path.dirname(os.path.abspath(__file__))
        bv = binaryninja.BinaryViewType["ELF"].open(dname+"/../sample/impCall/x86_impCall.bin")
        bv.update_analysis_and_wait()
        
        target = 0
        for f in bv.functions:
            if f.name == "main":
                target = f.start

        print ("Finished Loading Binary")
        engine = analysis_engine.bn_engine(bv)
        ui_ = gui.riprWidget()

        p = test_harness.t_Packager(True, target, engine, ui=ui_)
        p.impCallStrategy = 'hook'
        p.dataStrategy = 'page'
        p.resolve_arguments = True
        p.package_function("x64_test")
        
        if not os.path.exists('/tmp/riprtest'):
            os.makedirs('/tmp/riprtest/')

        t = open('/tmp/riprtest/x86page_impCall.py', 'w+')
        t.write(p.codeobj.final)
        t.close()

        testProc = subprocess.check_output(['python', '/tmp/riprtest/x86page_impCall.py'])
        self.assertIn('1337', testProc) 

class armTest(unittest.TestCase):
    def test(self):
        print ("Starting Test")
        dname = os.path.dirname(os.path.abspath(__file__))
        bv = binaryninja.BinaryViewType["ELF"].open(dname+"/../sample/impCall/arm_impCall.bin")
        bv.update_analysis_and_wait()
        
        target = 0
        for f in bv.functions:
            if f.name == "main":
                target = f.start

        print ("Finished Loading Binary")
        engine = analysis_engine.bn_engine(bv)
        ui_ = gui.riprWidget()

        p = test_harness.t_Packager(True, target, engine, ui=ui_)
        p.impCallStrategy = 'hook'
        p.dataStrategy = 'page'
        p.resolve_arguments = True
        p.package_function("x64_test")
        
        if not os.path.exists('/tmp/riprtest'):
            os.makedirs('/tmp/riprtest/')

        t = open('/tmp/riprtest/arm_impCall.py', 'w+')
        t.write(p.codeobj.final)
        t.close()

        testProc = subprocess.check_output(['python', '/tmp/riprtest/arm_impCall.py'])
        self.assertIn('1337', testProc) 

class armnopTest(unittest.TestCase):
    def test(self):
        print ("Starting Test")
        dname = os.path.dirname(os.path.abspath(__file__))
        bv = binaryninja.BinaryViewType["ELF"].open(dname+"/../sample/impCall/arm_impCall.bin")
        bv.update_analysis_and_wait()
        
        target = 0
        for f in bv.functions:
            if f.name == "main":
                target = f.start

        print ("Finished Loading Binary")
        engine = analysis_engine.bn_engine(bv)
        ui_ = gui.riprWidget()

        p = test_harness.t_Packager(True, target, engine, ui=ui_)
        p.impCallStrategy = 'nop'
        p.dataStrategy = 'section'
        p.resolve_arguments = True
        p.package_function("x64_test")
        
        if not os.path.exists('/tmp/riprtest'):
            os.makedirs('/tmp/riprtest/')

        t = open('/tmp/riprtest/armnop_impCall.py', 'w+')
        t.write(p.codeobj.final)
        t.close()

        testProc = subprocess.check_output(['python', '/tmp/riprtest/armnop_impCall.py'])
        self.assertIn('1337', testProc) 


if __name__ == '__main__':
    unittest.main()

