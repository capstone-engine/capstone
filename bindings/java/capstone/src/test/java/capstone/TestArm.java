// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013
// Andreas "PAX" L&uuml;ck <onkelpax-git@yahoo.de>, 2016 
package capstone;

import static capstone.Arm_const.ARM_CC_AL;
import static capstone.Arm_const.ARM_CC_INVALID;
import static capstone.Arm_const.ARM_OP_CIMM;
import static capstone.Arm_const.ARM_OP_FP;
import static capstone.Arm_const.ARM_OP_IMM;
import static capstone.Arm_const.ARM_OP_MEM;
import static capstone.Arm_const.ARM_OP_PIMM;
import static capstone.Arm_const.ARM_OP_REG;
import static capstone.Arm_const.ARM_OP_SETEND;
import static capstone.Arm_const.ARM_OP_SYSREG;
import static capstone.Arm_const.ARM_SETEND_BE;
import static capstone.Arm_const.ARM_SFT_INVALID;

import org.junit.Test;

import capstone.Capstone.CsInsn;
import capstone.utils.AssemblyDetailDumper;

public class TestArm extends TestTemplate {
	private static final String ARM_CODE = "EDFFFFEB04e02de500000000e08322e5f102030e0000a0e30230c1e7000053e3000201f10540d0e8";

	private static final String ARM_CODE2 = "d1e800f0f02404071f3cf2c000004ff00001466c";

	private static final String THUMB_CODE2 = "4ff00001bde80088d1e800f018bfadbff3ff0b0c86f3008980f3008c4ffa99f6d0ffa201";

	private static final String THUMB_CODE = "7047eb4683b0c9681fb130bfaff32084";

	private static class ARMDetailDumper extends AssemblyDetailDumper {
		public ARMDetailDumper(Capstone disassembler, CsInsn[] disassembly) {
			super(disassembler, disassembly);
		}

		@Override
		protected void printInstructionDetails(CsInsn instruction) {
			output.printf("0x%x:\t%s\t%s\n", instruction.address, instruction.mnemonic, instruction.opStr);

			Arm.OpInfo operands = (Arm.OpInfo) instruction.operands;

			if (operands.op.length != 0) {
				output.printf("\top_count: %d\n", operands.op.length);
				for (int c = 0; c < operands.op.length; c++) {
					Arm.Operand i = (Arm.Operand) operands.op[c];
					String imm = hex(i.value.imm);
					if (i.type == ARM_OP_SYSREG)
						output.printf("\t\toperands[%d].type: SYSREG = %d\n", c, i.value.reg);
					if (i.type == ARM_OP_REG)
						output.printf("\t\toperands[%d].type: REG = %s\n", c, instruction.regName(i.value.reg));
					if (i.type == ARM_OP_IMM)
						output.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
					if (i.type == ARM_OP_PIMM)
						output.printf("\t\toperands[%d].type: P-IMM = %d\n", c, i.value.imm);
					if (i.type == ARM_OP_CIMM)
						output.printf("\t\toperands[%d].type: C-IMM = %d\n", c, i.value.imm);
					if (i.type == ARM_OP_SETEND)
						output.printf("\t\toperands[%d].type: SETEND = %s\n", c,
								i.value.setend == ARM_SETEND_BE ? "be" : "le");
					if (i.type == ARM_OP_FP)
						output.printf("\t\toperands[%d].type: FP = %f\n", c, i.value.fp);
					if (i.type == ARM_OP_MEM) {
						output.printf("\t\toperands[%d].type: MEM\n", c);
						String base = instruction.regName(i.value.mem.base);
						String index = instruction.regName(i.value.mem.index);
						if (base != null)
							output.printf("\t\t\toperands[%d].mem.base: REG = %s\n", c, base);
						if (index != null)
							output.printf("\t\t\toperands[%d].mem.index: REG = %s\n", c, index);
						if (i.value.mem.scale != 1)
							output.printf("\t\t\toperands[%d].mem.scale: %d\n", c, (i.value.mem.scale));
						if (i.value.mem.disp != 0)
							output.printf("\t\t\toperands[%d].mem.disp: 0x%x\n", c, (i.value.mem.disp));
					}
					if (i.vector_index > 0)
						output.printf("\t\t\toperands[%d].vector_index = %d\n", c, (i.vector_index));
					if (i.shift.type != ARM_SFT_INVALID && i.shift.value > 0)
						output.printf("\t\t\tShift: %d = %d\n", i.shift.type, i.shift.value);
					if (i.subtracted)
						output.printf("\t\t\toperands[%d].subtracted = True\n", c);
				}
			}
			if (operands.writeback)
				output.println("\tWrite-back: True");

			if (operands.updateFlags)
				output.println("\tUpdate-flags: True");

			if (operands.cc != ARM_CC_AL && operands.cc != ARM_CC_INVALID)
				output.printf("\tCode condition: %d\n", operands.cc);

			if (operands.cpsMode > 0)
				output.printf("\tCPSI-mode: %d\n", operands.cpsMode);

			if (operands.cpsFlag > 0)
				output.printf("\tCPSI-flag: %d\n", operands.cpsFlag);

			if (operands.vectorData > 0)
				output.printf("\tVector-data: %d\n", operands.vectorData);

			if (operands.vectorSize > 0)
				output.printf("\tVector-size: %d\n", operands.vectorSize);

			if (operands.usermode)
				output.printf("\tUser-mode: True\n");

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
		return AssemblyDetailDumper.createDisassemblyDetails(new ARMDetailDumper(disassembler, disassembly));
	}

	@Test
	public void testArmNormalSyntax() throws Exception {
		// ARM
		CsInsn[] disassembly = createDisassembler(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_ARM, hexString2Byte(ARM_CODE));
		assertDisassembly("/ARM/ARM/assembly_normal_syntax.asm", createDisassemblyDetails(disassembly));
	}

	@Test
	public void testThumbNormalSyntax_1() throws Exception {
		// Thumb
		CsInsn[] disassembly = createDisassembler(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_THUMB,
				hexString2Byte(THUMB_CODE));
		assertDisassembly("/ARM/THUMB/assembly_normal_syntax_1.asm", createDisassemblyDetails(disassembly));
	}

	@Test
	public void testThumbNormalSyntax_2() throws Exception {
		// Thumb-mixed
		CsInsn[] disassembly = createDisassembler(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_THUMB,
				hexString2Byte(ARM_CODE2));
		assertDisassembly("/ARM/THUMB/assembly_normal_syntax_2.asm", createDisassemblyDetails(disassembly));
	}

	@Test
	public void testThumbNOREGNAMESyntax() throws Exception {
		// Thumb-2 & register named with numbers
		CsInsn[] disassembly = createDisassembler(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_THUMB,
				Capstone.CS_OPT_SYNTAX_NOREGNAME, hexString2Byte(THUMB_CODE2));
		assertDisassembly("/ARM/THUMB/assembly_noregname_syntax.asm", createDisassemblyDetails(disassembly));
	}
}
