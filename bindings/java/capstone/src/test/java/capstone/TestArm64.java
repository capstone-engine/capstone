// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013
// Andreas "PAX" L&uuml;ck <onkelpax-git@yahoo.de>, 2016 
package capstone;

import static capstone.Arm64_const.ARM64_CC_AL;
import static capstone.Arm64_const.ARM64_CC_INVALID;
import static capstone.Arm64_const.ARM64_EXT_INVALID;
import static capstone.Arm64_const.ARM64_OP_BARRIER;
import static capstone.Arm64_const.ARM64_OP_CIMM;
import static capstone.Arm64_const.ARM64_OP_FP;
import static capstone.Arm64_const.ARM64_OP_IMM;
import static capstone.Arm64_const.ARM64_OP_MEM;
import static capstone.Arm64_const.ARM64_OP_PSTATE;
import static capstone.Arm64_const.ARM64_OP_REG;
import static capstone.Arm64_const.ARM64_OP_REG_MRS;
import static capstone.Arm64_const.ARM64_OP_REG_MSR;
import static capstone.Arm64_const.ARM64_SFT_INVALID;
import static capstone.Arm64_const.ARM64_VAS_INVALID;
import static capstone.Arm64_const.ARM64_VESS_INVALID;

import org.junit.Test;

import capstone.Capstone.CsInsn;
import capstone.utils.AssemblyDetailDumper;

public class TestArm64 extends TestTemplate {
	private static final String ARM64_CODE = "090038d5bf4000d50c0513d52050020e20e43d0f0018a05fa200ae9e9f3703d5bf3303d5df3f03d5217c029b217c00530040214be10b40b9200481da2008028b105be83c";

	private static class ARM64DetailDumper extends AssemblyDetailDumper {
		public ARM64DetailDumper(Capstone disassembler, CsInsn[] disassembly) {
			super(disassembler, disassembly);
		}

		@Override
		protected void printInstructionDetails(CsInsn instruction) {
			output.printf("0x%x:\t%s\t%s\n", instruction.address, instruction.mnemonic, instruction.opStr);

			Arm64.OpInfo operands = (Arm64.OpInfo) instruction.operands;

			if (operands.op.length != 0) {
				output.printf("\top_count: %d\n", operands.op.length);
				for (int c = 0; c < operands.op.length; c++) {
					Arm64.Operand i = (Arm64.Operand) operands.op[c];
					String imm = hex(i.value.imm);
					if (i.type == ARM64_OP_REG)
						output.printf("\t\toperands[%d].type: REG = %s\n", c, instruction.regName(i.value.reg));
					if (i.type == ARM64_OP_REG_MRS)
						output.printf("\t\toperands[%d].type: REG_MRS = 0x%x\n", c, i.value.reg);
					if (i.type == ARM64_OP_REG_MSR)
						output.printf("\t\toperands[%d].type: REG_MSR = 0x%x\n", c, i.value.reg);
					if (i.type == ARM64_OP_PSTATE)
						output.printf("\t\toperands[%d].type: PSTATE = 0x%x\n", c, i.value.imm);
					if (i.type == ARM64_OP_BARRIER)
						output.printf("\t\toperands[%d].type: BARRIER = 0x%x\n", c, i.value.imm);

					if (i.type == ARM64_OP_IMM)
						output.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
					if (i.type == ARM64_OP_CIMM)
						output.printf("\t\toperands[%d].type: C-IMM = %d\n", c, i.value.imm);
					if (i.type == ARM64_OP_FP)
						output.printf("\t\toperands[%d].type: FP = %f\n", c, i.value.fp);
					if (i.type == ARM64_OP_MEM) {
						output.printf("\t\toperands[%d].type: MEM\n", c);
						String base = instruction.regName(i.value.mem.base);
						String index = instruction.regName(i.value.mem.index);
						if (base != null)
							output.printf("\t\t\toperands[%d].mem.base: REG = %s\n", c, base);
						if (index != null)
							output.printf("\t\t\toperands[%d].mem.index: REG = %s\n", c, index);
						if (i.value.mem.disp != 0)
							output.printf("\t\t\toperands[%d].mem.disp: 0x%x\n", c, i.value.mem.disp);
					}
					if (i.shift.type != ARM64_SFT_INVALID && i.shift.value > 0)
						output.printf("\t\t\tShift: type = %d, value = %d\n", i.shift.type, i.shift.value);
					if (i.ext != ARM64_EXT_INVALID)
						output.printf("\t\t\tExt: %d\n", i.ext);
					if (i.vas != ARM64_VAS_INVALID)
						output.printf("\t\t\tVector Arrangement Specifier: 0x%x\n", i.vas);
					if (i.vess != ARM64_VESS_INVALID)
						output.printf("\t\t\tVector Element Size Specifier: %d\n", i.vess);
					if (i.vector_index != -1)
						output.printf("\t\t\tVector Index: %d\n", i.vector_index);

				}
			}

			if (operands.writeback)
				output.println("\tWrite-back: True");

			if (operands.updateFlags)
				output.println("\tUpdate-flags: True");

			if (operands.cc != ARM64_CC_AL && operands.cc != ARM64_CC_INVALID)
				output.printf("\tCode-condition: %d\n", operands.cc);

			output.println();
		}
	}

	/**
	 * Obtains detailed assembly information of the specified disassembly.
	 * 
	 * @param disassembly
	 *            An array with assembler commands (and operands) extracted from
	 *            machine code.
	 * @return A dump of the assembler commands and information about their
	 *         occupied total bytes and affected registers etc.
	 * @throws Exception
	 *             If any error occurs.
	 */
	private String createDisassemblyDetails(CsInsn[] disassembly) throws Exception {
		return AssemblyDetailDumper.createDisassemblyDetails(new ARM64DetailDumper(disassembler, disassembly));
	}

	@Test
	public void testARM64NormalSyntax() throws Exception {
		// ARM-64
		CsInsn[] disassembly = createDisassembler(Capstone.CS_ARCH_ARM64, Capstone.CS_MODE_ARM,
				hexString2Byte(ARM64_CODE));
		assertDisassembly("/ARM64/ARM/assembly_normal_syntax.asm", createDisassemblyDetails(disassembly));
	}
}
