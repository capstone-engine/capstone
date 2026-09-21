from capstone import *
from capstone.riscv import *
from capstone.riscv_const import *
import sys

def test():
    print("Test test_riscv_sysreg (Python)")
    errors = []
    # csrr a0, sstatus (0x10002573)
    # csrr a0, mtvec   (0x30502573)
    # csrr a0, mcause  (0x34202573)
    CODE = b"\x73\x25\x00\x10\x73\x25\x50\x30\x73\x25\x20\x34"
    
    expected_sysregs = [
        RISCV_SYSREG_SSTATUS,
        RISCV_SYSREG_MTVEC,
        RISCV_SYSREG_MCAUSE,
    ]
    
    try:
        md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
        md.detail = True
        
        count = 0
        for insn in md.disasm(CODE, 0):
            found_sysreg = False
            for op in insn.operands:
                if op.type == RISCV_OP_CSR:
                    if count >= len(expected_sysregs):
                        errors.append(f"FAIL: Found CSR operand in instruction {count}, but only {len(expected_sysregs)} expected.")
                        break
                    
                    if op.csr != expected_sysregs[count]:
                        errors.append(f"FAIL: Expected sysreg {expected_sysregs[count]}, got {op.csr}")
                    
                    if op.csr == RISCV_SYSREG_SSTATUS:
                        print("    Recognized SSTATUS")
                    elif op.csr == RISCV_SYSREG_MTVEC:
                        print("    Recognized MTVEC")
                    elif op.csr == RISCV_SYSREG_MCAUSE:
                        print("    Recognized MCAUSE")
                    
                    found_sysreg = True
            
            if not found_sysreg:
                errors.append(f"FAIL: No CSR operand found in instruction {count}")
                
            count += 1
        
        if count != 3:
            errors.append(f"FAIL: Expected 3 instructions, got {count}")
    except CsError as e:
        errors.append(str(e))
        
    return errors

if __name__ == '__main__':
    errs = test()
    if not errs:
        print("Python sysreg test PASSED")
        sys.exit(0)
    else:
        print("Python sysreg test FAILED")
        for e in errs:
            print(f"  {e}")
        sys.exit(1)
