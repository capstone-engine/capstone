// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013-2014
// Andreas "PAX" L&uuml;ck <onkelpax-git@yahoo.de>, 2016 
package capstone;

import static capstone.Sparc_const.SPARC_OP_IMM;
import static capstone.Sparc_const.SPARC_OP_MEM;
import static capstone.Sparc_const.SPARC_OP_REG;
import static capstone.Sparc_const.SPARC_REG_INVALID;

import org.junit.Test;

import capstone.Capstone.CsInsn;
import capstone.utils.AssemblyDetailDumper;

public class TestSparc extends TestTemplate {
	private static final String SPARC_CODE = "80a0400285c2600885e8200181e8000090102001d5f610162100000a860040020100000012bfffff10bfffffa00200090dbfffffd4206000d44e00162ac28003";

	private static final String SPARCV9_CODE = "81a80a2489a0102089a01a6089a000e0";

	private static class SparcDetailDumper extends AssemblyDetailDumper {
		public SparcDetailDumper(Capstone disassembler, CsInsn[] disassembly) {
			super(disassembler, disassembly);
		}

		@Override
		protected void printInstructionDetails(CsInsn instruction) {
			output.printf("0x%x:\t%s\t%s\n", instruction.address, instruction.mnemonic, instruction.opStr);

			Sparc.OpInfo operands = (Sparc.OpInfo) instruction.operands;

			if (operands.op.length != 0) {
				output.printf("\top_count: %d\n", operands.op.length);
				for (int c = 0; c < operands.op.length; c++) {
					Sparc.Operand i = (Sparc.Operand) operands.op[c];
					if (i.type == SPARC_OP_REG)
						output.printf("\t\toperands[%d].type: REG = %s\n", c, instruction.regName(i.value.reg));
					if (i.type == SPARC_OP_IMM)
						output.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
					if (i.type == SPARC_OP_MEM) {
						output.printf("\t\toperands[%d].type: MEM\n", c);
						if (i.value.mem.base != SPARC_REG_INVALID)
							output.printf("\t\t\toperands[%d].mem.base: REG = %s\n", c,
									instruction.regName(i.value.mem.base));
						if (i.value.mem.index != SPARC_REG_INVALID)
							output.printf("\t\t\toperands[%d].mem.index: REG = %s\n", c,
									instruction.regName(i.value.mem.index));
						if (i.value.mem.disp != 0)
							output.printf("\t\t\toperands[%d].mem.disp: 0x%x\n", c, i.value.mem.disp);
					}
				}
			}

			if (operands.cc != 0)
				output.printf("\tCode condition: %d\n", operands.cc);

			if (operands.hint != 0)
				output.printf("\tHint code: %d\n", operands.hint);

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
		return AssemblyDetailDumper.createDisassemblyDetails(new SparcDetailDumper(disassembler, disassembly));
	}

	@Test
	public void testBigEndianNormalSyntax() throws Exception {
		// Sparc
		CsInsn[] disassembly = createDisassembler(Capstone.CS_ARCH_SPARC, Capstone.CS_MODE_BIG_ENDIAN,
				hexString2Byte(SPARC_CODE));
		assertDisassembly("/Sparc/BigEndian/assembly_normal_syntax.asm", createDisassemblyDetails(disassembly));
	}

	@Test
	public void testBigEndianV9NormalSyntax() throws Exception {
		// SparcV9
		CsInsn[] disassembly = createDisassembler(Capstone.CS_ARCH_SPARC,
				Capstone.CS_MODE_BIG_ENDIAN + Capstone.CS_MODE_V9, hexString2Byte(SPARCV9_CODE));
		assertDisassembly("/Sparc/V9/assembly_normal_syntax.asm", createDisassemblyDetails(disassembly));
	}
}
