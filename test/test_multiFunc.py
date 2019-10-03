import unittest
import subprocess
import sys,os

from ripr import test_harness
from ripr import gui
from ripr import analysis_engine

import binaryninja

class x64_multiTest(unittest.TestCase):
    def test(self):
        print ("Starting Test")
        binary = "x64_multiFunc"
        dname = os.path.dirname(os.path.abspath(__file__))

        bv = binaryninja.BinaryViewType["ELF"].open(dname+"/../sample/multiFunc/%s" % binary)
        bv.update_analysis_and_wait()
        
        target = 0
        for f in bv.functions:
            if f.name == "func_1":
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

        t = open('/tmp/riprtest/%s.py' % binary, 'w+')
        t.write(p.codeobj.final)
        t.close()

        testProc = subprocess.check_output(['python', '/tmp/riprtest/%s.py' % binary])
        testProc = testProc.split("\n")

        self.assertIn('15', testProc[-2]) 

class x86_multiTest(unittest.TestCase):
    def test(self):
        print ("Starting Test")
        binary = "x86_multiFunc"
        dname = os.path.dirname(os.path.abspath(__file__))

        bv = binaryninja.BinaryViewType["ELF"].open(dname+"/../sample/multiFunc/%s" % binary)
        bv.update_analysis_and_wait()
        
        target = 0
        for f in bv.functions:
            if f.name == "func_1":
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

        t = open('/tmp/riprtest/%s.py' % binary, 'w+')
        t.write(p.codeobj.final)
        t.close()

        testProc = subprocess.check_output(['python', '/tmp/riprtest/%s.py' % binary])
        testProc = testProc.split("\n")

        self.assertIn('15', testProc[-2]) 

class arm_multiTest(unittest.TestCase):
    def test(self):
        print ("Starting Test")
        binary = "arm_multiFunc"
        dname = os.path.dirname(os.path.abspath(__file__))

        bv = binaryninja.BinaryViewType["ELF"].open(dname+"/../sample/multiFunc/%s" % binary)
        bv.update_analysis_and_wait()
        
        target = 0
        for f in bv.functions:
            if f.name == "func_1":
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

        t = open('/tmp/riprtest/%s.py' % binary, 'w+')
        t.write(p.codeobj.final)
        t.close()

        testProc = subprocess.check_output(['python', '/tmp/riprtest/%s.py' % binary])
        testProc = testProc.split("\n")

        self.assertIn('15', testProc[-2]) 


