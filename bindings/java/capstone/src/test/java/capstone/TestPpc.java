// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013
// Andreas "PAX" L&uuml;ck <onkelpax-git@yahoo.de>, 2016 
package capstone;

import static capstone.Ppc_const.PPC_OP_IMM;
import static capstone.Ppc_const.PPC_OP_MEM;
import static capstone.Ppc_const.PPC_OP_REG;
import static capstone.Ppc_const.PPC_REG_INVALID;

import org.junit.Test;

import capstone.Capstone.CsInsn;
import capstone.utils.AssemblyDetailDumper;

public class TestPpc extends TestTemplate {
	private static final String PPC_CODE = "80200000803f00001043230ed04400804c4322022d0300807c4320147c4320934f2000214cc8002140820014";

	private static class PPCDetailDumper extends AssemblyDetailDumper {
		public PPCDetailDumper(Capstone disassembler, CsInsn[] disassembly) {
			super(disassembler, disassembly);
		}

		@Override
		protected void printInstructionDetails(CsInsn instruction) {
			output.printf("0x%x:\t%s\t%s\n", instruction.address, instruction.mnemonic, instruction.opStr);

			Ppc.OpInfo operands = (Ppc.OpInfo) instruction.operands;

			if (operands.op.length != 0) {
				output.printf("\top_count: %d\n", operands.op.length);
				for (int c = 0; c < operands.op.length; c++) {
					Ppc.Operand i = (Ppc.Operand) operands.op[c];
					if (i.type == PPC_OP_REG)
						output.printf("\t\toperands[%d].type: REG = %s\n", c, instruction.regName(i.value.reg));
					if (i.type == PPC_OP_IMM)
						output.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
					if (i.type == PPC_OP_MEM) {
						output.printf("\t\toperands[%d].type: MEM\n", c);
						if (i.value.mem.base != PPC_REG_INVALID)
							output.printf("\t\t\toperands[%d].mem.base: REG = %s\n", c,
									instruction.regName(i.value.mem.base));
						if (i.value.mem.disp != 0)
							output.printf("\t\t\toperands[%d].mem.disp: 0x%x\n", c, i.value.mem.disp);
					}
				}
			}

			if (operands.bc != 0)
				output.printf("\tBranch code: %d\n", operands.bc);

			if (operands.bh != 0)
				output.printf("\tBranch hint: %d\n", operands.bh);

			if (operands.updateCr0)
				output.printf("\tUpdate-CR0: True\n");

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
		return AssemblyDetailDumper.createDisassemblyDetails(new PPCDetailDumper(disassembler, disassembly));
	}

	@Test
	public void testPPCBigEndianNormalSyntax() throws Exception {
		// PPC-64
		CsInsn[] disassembly = createDisassembler(Capstone.CS_ARCH_PPC, Capstone.CS_MODE_BIG_ENDIAN,
				hexString2Byte(PPC_CODE));
		assertDisassembly("/PPC/BigEndian/assembly_normal_syntax.asm", createDisassemblyDetails(disassembly));
	}
}
