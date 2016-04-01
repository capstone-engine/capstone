// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013-2014
// Andreas "PAX" L&uuml;ck <onkelpax-git@yahoo.de>, 2016 
package capstone;

import static capstone.Xcore_const.XCORE_OP_IMM;
import static capstone.Xcore_const.XCORE_OP_MEM;
import static capstone.Xcore_const.XCORE_OP_REG;
import static capstone.Xcore_const.XCORE_REG_INVALID;

import org.junit.Test;

import capstone.Capstone.CsInsn;
import capstone.utils.AssemblyDetailDumper;

public class TestXcore extends TestTemplate {
	private static final String XCORE_CODE = "fe0ffe171317c6feec1797f8ec4f1ffdec3707f2455bf9fa02061b1009fdeca7";

	private static class XCoreDetailDumper extends AssemblyDetailDumper {
		public XCoreDetailDumper(Capstone disassembler, CsInsn[] disassembly) {
			super(disassembler, disassembly);
		}

		@Override
		protected void printInstructionDetails(CsInsn instruction) {
			output.printf("0x%x:\t%s\t%s\n", instruction.address, instruction.mnemonic, instruction.opStr);

			Xcore.OpInfo operands = (Xcore.OpInfo) instruction.operands;

			if (operands.op.length != 0) {
				output.printf("\top_count: %d\n", operands.op.length);
				for (int c = 0; c < operands.op.length; c++) {
					Xcore.Operand i = (Xcore.Operand) operands.op[c];
					if (i.type == XCORE_OP_REG)
						output.printf("\t\toperands[%d].type: REG = %s\n", c, instruction.regName(i.value.reg));
					if (i.type == XCORE_OP_IMM)
						output.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
					if (i.type == XCORE_OP_MEM) {
						output.printf("\t\toperands[%d].type: MEM\n", c);
						if (i.value.mem.base != XCORE_REG_INVALID)
							output.printf("\t\t\toperands[%d].mem.base: REG = %s\n", c,
									instruction.regName(i.value.mem.base));
						if (i.value.mem.index != XCORE_REG_INVALID)
							output.printf("\t\t\toperands[%d].mem.index: REG = %s\n", c,
									instruction.regName(i.value.mem.index));
						if (i.value.mem.disp != 0)
							output.printf("\t\t\toperands[%d].mem.disp: 0x%x\n", c, i.value.mem.disp);
						if (i.value.mem.direct != 1)
							output.printf("\t\t\toperands[%d].mem.direct: -1\n", c);
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
		return AssemblyDetailDumper.createDisassemblyDetails(new XCoreDetailDumper(disassembler, disassembly));
	}

	@Test
	public void testBigEndianNormalSyntax() throws Exception {
		// XCore
		CsInsn[] disassembly = createDisassembler(Capstone.CS_ARCH_XCORE, Capstone.CS_MODE_BIG_ENDIAN,
				hexString2Byte(XCORE_CODE));
		assertDisassembly("/XCore/BigEndian/assembly_normal_syntax.asm", createDisassemblyDetails(disassembly));
	}
}
