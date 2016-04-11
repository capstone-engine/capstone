// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013-2014
// Andreas "PAX" L&uuml;ck <onkelpax-git@yahoo.de>, 2016 
package capstone;

import static capstone.Sysz_const.SYSZ_OP_ACREG;
import static capstone.Sysz_const.SYSZ_OP_IMM;
import static capstone.Sysz_const.SYSZ_OP_MEM;
import static capstone.Sysz_const.SYSZ_OP_REG;
import static capstone.Sysz_const.SYSZ_REG_INVALID;

import org.junit.Test;

import capstone.Capstone.CsInsn;
import capstone.utils.AssemblyDetailDumper;

public class TestSystemz extends TestTemplate {
	private static final String SYSZ_CODE = "ed000000001a5a0f1fffc2098000000007f7eb2affff7f57e301ffff7f57eb00f0000024b24f0078ec180000c17f";

	private static class SystemZDetailDumper extends AssemblyDetailDumper {
		public SystemZDetailDumper(Capstone disassembler, CsInsn[] disassembly) {
			super(disassembler, disassembly);
		}

		@Override
		protected void printInstructionDetails(CsInsn instruction) {
			output.printf("0x%x:\t%s\t%s\n", instruction.address, instruction.mnemonic, instruction.opStr);

			Systemz.OpInfo operands = (Systemz.OpInfo) instruction.operands;

			if (operands.op.length != 0) {
				output.printf("\top_count: %d\n", operands.op.length);
				for (int c = 0; c < operands.op.length; c++) {
					Systemz.Operand i = (Systemz.Operand) operands.op[c];
					if (i.type == SYSZ_OP_REG)
						output.printf("\t\toperands[%d].type: REG = %s\n", c, instruction.regName(i.value.reg));
					if (i.type == SYSZ_OP_ACREG)
						output.printf("\t\toperands[%d].type: ACREG = %s\n", c, i.value.reg);
					if (i.type == SYSZ_OP_IMM)
						output.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
					if (i.type == SYSZ_OP_MEM) {
						output.printf("\t\toperands[%d].type: MEM\n", c);
						if (i.value.mem.base != SYSZ_REG_INVALID)
							output.printf("\t\t\toperands[%d].mem.base: REG = %s\n", c, instruction.regName(i.value.mem.base));
						if (i.value.mem.index != SYSZ_REG_INVALID)
							output.printf("\t\t\toperands[%d].mem.index: REG = %s\n", c,
									instruction.regName(i.value.mem.index));
						if (i.value.mem.length != 0)
							output.printf("\t\t\toperands[%d].mem.length: 0x%x\n", c, i.value.mem.disp);
						if (i.value.mem.disp != 0)
							output.printf("\t\t\toperands[%d].mem.disp: 0x%x\n", c, i.value.mem.disp);
					}
				}
			}

			if (operands.cc != 0)
				output.printf("\tConditional code: %d\n", operands.cc);

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
		return AssemblyDetailDumper.createDisassemblyDetails(new SystemZDetailDumper(disassembler, disassembly));
	}

	@Test
	public void testSystemZNormalSyntax() throws Exception {
		// SystemZ
		CsInsn[] disassembly = createDisassembler(Capstone.CS_ARCH_SYSZ, 0, hexString2Byte(SYSZ_CODE));
		assertDisassembly("/SystemZ/assembly_normal_syntax.asm", createDisassemblyDetails(disassembly));
	}
}
