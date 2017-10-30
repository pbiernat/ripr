from binaryninja import *

class ilVar(object):
    def __hash__(self):
        return self.var.__hash__()

    def __eq__(self, other):
        return self.var == other.var

    def __init__(self, var, mil):
        self.var = var
        self.mil = mil
        
        self.reg = None
        try:
            r = self.mil.low_level_il
            while(hasattr(r, 'src')):
                r = r.src

            for op in r.operands:
                if op.operation in [LowLevelILOperation.LLIL_REG,\
                                    LowLevelILOperation.LLIL_REG_SSA]:
                    self.reg = op.tokens[0]
                    break
        except:
            pass

class riprArg(object):
    def __init__(self, _type, num):
        self.type = _type
        self.num = num
        self.pointerDepth = str(self.type).count("*")

class convenienceScanner(object):
    def __init__(self, engine):
        self.engine = engine

    def argIdent(self, addr, isFunc):
        fobj = self.engine.bv.get_functions_containing(addr)
        if len(fobj) > 1:
            return None
        fobj = fobj[0]
        if (isFunc):
            ret = []
            ftype = fobj.function_type
            for i in range(0, len(ftype.parameters)):
                arg = ftype.parameters[i]
                ret.append(riprArg(arg.type, i))

            return ret
            
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
                self.engine.highlight_instr(bb.keys()[0], uVar.mil.address, "orange") 

            return unset_vars
