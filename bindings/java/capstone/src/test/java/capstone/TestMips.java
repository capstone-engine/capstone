// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013
// Andreas "PAX" L&uuml;ck <onkelpax-git@yahoo.de>, 2016 
package capstone;

import static capstone.Mips_const.MIPS_OP_IMM;
import static capstone.Mips_const.MIPS_OP_MEM;
import static capstone.Mips_const.MIPS_OP_REG;

import org.junit.Test;

import capstone.Capstone.CsInsn;
import capstone.utils.AssemblyDetailDumper;

public class TestMips extends TestTemplate {
	private static final String MIPS_CODE = "0C100097000000002402000c8fa2000034213456";

	private static final String MIPS_CODE2 = "56342134c2170100";

	private static class MIPSDetailDumper extends AssemblyDetailDumper {
		public MIPSDetailDumper(Capstone disassembler, CsInsn[] disassembly) {
			super(disassembler, disassembly);
		}

		@Override
		protected void printInstructionDetails(CsInsn instruction) {
			output.printf("0x%x:\t%s\t%s\n", instruction.address, instruction.mnemonic, instruction.opStr);

			Mips.OpInfo operands = (Mips.OpInfo) instruction.operands;

			if (operands.op.length != 0) {
				output.printf("\top_count: %d\n", operands.op.length);
				for (int c = 0; c < operands.op.length; c++) {
					Mips.Operand i = (Mips.Operand) operands.op[c];
					String imm = hex(i.value.imm);
					if (i.type == MIPS_OP_REG)
						output.printf("\t\toperands[%d].type: REG = %s\n", c, instruction.regName(i.value.reg));
					if (i.type == MIPS_OP_IMM)
						output.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
					if (i.type == MIPS_OP_MEM) {
						output.printf("\t\toperands[%d].type: MEM\n", c);
						String base = instruction.regName(i.value.mem.base);
						if (base != null)
							output.printf("\t\t\toperands[%d].mem.base: REG = %s\n", c, base);
						if (i.value.mem.disp != 0)
							output.printf("\t\t\toperands[%d].mem.disp: %s\n", c, hex(i.value.mem.disp));
					}
				}
			}

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
		return AssemblyDetailDumper.createDisassemblyDetails(new MIPSDetailDumper(disassembler, disassembly));
	}

	@Test
	public void test32bitNormalSyntax() throws Exception {
		// MIPS-32 (Big-endian)
		CsInsn[] disassembly = createDisassembler(Capstone.CS_ARCH_MIPS,
				Capstone.CS_MODE_MIPS32 + Capstone.CS_MODE_BIG_ENDIAN, hexString2Byte(MIPS_CODE));
		assertDisassembly("/MIPS/MIPS32/assembly_normal_syntax.asm", createDisassemblyDetails(disassembly));
	}

	@Test
	public void test64bitNormalSyntax() throws Exception {
		// MIPS-64-EL (Little-endian)
		CsInsn[] disassembly = createDisassembler(Capstone.CS_ARCH_MIPS,
				Capstone.CS_MODE_MIPS64 + Capstone.CS_MODE_LITTLE_ENDIAN, hexString2Byte(MIPS_CODE2));
		assertDisassembly("/MIPS/MIPS64/assembly_normal_syntax.asm", createDisassemblyDetails(disassembly));
	}
}
