// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013
// Andreas "PAX" L&uuml;ck <onkelpax-git@yahoo.de>, 2016 
package capstone;

import static capstone.X86_const.X86_AVX_BCAST_INVALID;
import static capstone.X86_const.X86_OP_FP;
import static capstone.X86_const.X86_OP_IMM;
import static capstone.X86_const.X86_OP_MEM;
import static capstone.X86_const.X86_OP_REG;

import org.junit.Test;

import capstone.Capstone.CsInsn;
import capstone.utils.AssemblyDetailDumper;

public class TestX86 extends TestTemplate {
	private static final String X86_CODE16 = "8d4c320801d881c6341200000523010000368b849123010000418d8439896700008d8789670000b4c6";
	
	private static final String X86_CODE32 = "8d4c320801d881c6341200000523010000368b849123010000418d8439896700008d8789670000b4c6";

	private static final String X86_CODE64 = "55488b05b8130000";
	
	private static class X86DetailDumper extends AssemblyDetailDumper {
		public X86DetailDumper(Capstone disassembler, CsInsn[] disassembly) {
			super(disassembler, disassembly);
		}

		@Override
		public void printInstructionDetails(CsInsn instruction) {
			output.printf("0x%x:\t%s\t%s\n", instruction.address, instruction.mnemonic, instruction.opStr);

			X86.OpInfo operands = (X86.OpInfo) instruction.operands;

			output.printf("\tPrefix: %s\n", array2hex(operands.prefix));

			output.printf("\tOpcode: %s\n", array2hex(operands.opcode));

			// print REX prefix (non-zero value is relevant for x86_64)
			output.printf("\trex: 0x%x\n", operands.rex);

			// print address size
			output.printf("\taddr_size: %d\n", operands.addrSize);

			// print modRM byte
			output.printf("\tmodrm: 0x%x\n", operands.modrm);

			// print displacement value
			output.printf("\tdisp: 0x%x\n", operands.disp);

			// SIB is not available in 16-bit mode
			if ((disassembler.mode & Capstone.CS_MODE_16) == 0) {
				// print SIB byte
				output.printf("\tsib: 0x%x\n", operands.sib);
				if (operands.sib != 0)
					output.printf("\t\tsib_base: %s\n\t\tsib_index: %s\n\t\tsib_scale: %d\n",
							instruction.regName(operands.sibBase), instruction.regName(operands.sibIndex),
							operands.sibScale);
			}

			if (operands.sseCC != 0)
				output.printf("\tsse_cc: %u\n", operands.sseCC);

			if (operands.avxCC != 0)
				output.printf("\tavx_cc: %u\n", operands.avxCC);

			if (operands.avxSae)
				output.printf("\tavx_sae: TRUE\n");

			if (operands.avxRm != 0)
				output.printf("\tavx_rm: %u\n", operands.avxRm);

			int count = instruction.opCount(X86_OP_IMM);
			if (count > 0) {
				output.printf("\timm_count: %d\n", count);
				for (int i = 0; i < count; i++) {
					int index = instruction.opIndex(X86_OP_IMM, i + 1);
					output.printf("\t\timms[%d]: 0x%x\n", i + 1, (operands.op[index].value.imm));
				}
			}

			if (operands.op.length != 0) {
				output.printf("\top_count: %d\n", operands.op.length);
				for (int c = 0; c < operands.op.length; c++) {
					X86.Operand i = (X86.Operand) operands.op[c];
					String imm = hex(i.value.imm);
					if (i.type == X86_OP_REG)
						output.printf("\t\toperands[%d].type: REG = %s\n", c, instruction.regName(i.value.reg));
					if (i.type == X86_OP_IMM)
						output.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
					if (i.type == X86_OP_FP)
						output.printf("\t\toperands[%d].type: FP = %f\n", c, i.value.fp);
					if (i.type == X86_OP_MEM) {
						output.printf("\t\toperands[%d].type: MEM\n", c);
						String segment = instruction.regName(i.value.mem.segment);
						String base = instruction.regName(i.value.mem.base);
						String index = instruction.regName(i.value.mem.index);
						if (segment != null)
							output.printf("\t\t\toperands[%d].mem.segment: REG = %s\n", c, segment);
						if (base != null)
							output.printf("\t\t\toperands[%d].mem.base: REG = %s\n", c, base);
						if (index != null)
							output.printf("\t\t\toperands[%d].mem.index: REG = %s\n", c, index);
						if (i.value.mem.scale != 1)
							output.printf("\t\t\toperands[%d].mem.scale: %d\n", c, i.value.mem.scale);
						if (i.value.mem.disp != 0)
							output.printf("\t\t\toperands[%d].mem.disp: 0x%x\n", c, i.value.mem.disp);
					}

					// AVX broadcast type
					if (i.avx_bcast != X86_AVX_BCAST_INVALID) {
						output.printf("\t\toperands[%d].avx_bcast: %d\n", c, i.avx_bcast);
					}

					// AVX zero opmask {z}
					if (i.avx_zero_opmask) {
						output.printf("\t\toperands[%d].avx_zero_opmask: TRUE\n", c);
					}

					output.printf("\t\toperands[%d].size: %d\n", c, i.size);
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
		return AssemblyDetailDumper.createDisassemblyDetails(new X86DetailDumper(disassembler, disassembly));
	}

	@Test
	public void test16bitIntelSyntax() throws Exception {
		// X86 16bit (Intel syntax)
		CsInsn[] disassembly = createDisassembler(Capstone.CS_ARCH_X86, Capstone.CS_MODE_16,
				hexString2Byte(X86_CODE16));
		assertDisassembly("/X86/16/assembly_intel_syntax.asm", createDisassemblyDetails(disassembly));
	}

	@Test
	public void test32bitAttSyntax() throws Exception {
		// X86 32 (AT&T syntax)
		CsInsn[] disassembly = createDisassembler(Capstone.CS_ARCH_X86, Capstone.CS_MODE_32, Capstone.CS_OPT_SYNTAX_ATT,
				hexString2Byte(X86_CODE32));
		assertDisassembly("/X86/32/assembly_att_syntax.asm", createDisassemblyDetails(disassembly));
	}

	@Test
	public void test32bitIntelSyntax() throws Exception {
		// X86 32 (Intel syntax)
		CsInsn[] disassembly = createDisassembler(Capstone.CS_ARCH_X86, Capstone.CS_MODE_32,
				hexString2Byte(X86_CODE32));
		assertDisassembly("/X86/32/assembly_intel_syntax.asm", createDisassemblyDetails(disassembly));
	}

	@Test
	public void test64bitIntelSyntax() throws Exception {
		// X86 64 (Intel syntax)
		CsInsn[] disassembly = createDisassembler(Capstone.CS_ARCH_X86, Capstone.CS_MODE_64,
				hexString2Byte(X86_CODE64));
		assertDisassembly("/X86/64/assembly_intel_syntax.asm", createDisassemblyDetails(disassembly));
	}
}
