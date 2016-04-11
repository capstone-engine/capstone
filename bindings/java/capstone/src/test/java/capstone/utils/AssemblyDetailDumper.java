package capstone.utils;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;

import capstone.Capstone;
import capstone.Capstone.CsInsn;

/**
 * Base class for assembly dumper implementations. They are expected to get a
 * disassembly and print detailed information about each assembler instruction
 * to {@link #output}.
 * 
 * @author Andreas "PAX" L&uuml;ck
 */
public abstract class AssemblyDetailDumper {
	protected final Capstone disassembler;

	protected final CsInsn[] disassembly;

	private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

	protected final PrintWriter output;

	/**
	 * @param disassembler
	 *            The disassembler instance that was used to create this
	 *            disassembly.
	 * @param disassembly
	 *            The concerning disassembly to be dumped.
	 */
	protected AssemblyDetailDumper(Capstone disassembler, CsInsn[] disassembly) {
		this.disassembler = disassembler;
		this.disassembly = disassembly;
		this.output = new PrintWriter(outputStream, true);
	}

	/**
	 * Responsible for printing detailed information about one single
	 * disassembly instruction.
	 * 
	 * @param instruction
	 *            The concerning assembler instruction to be dumped.
	 */
	protected abstract void printInstructionDetails(CsInsn instruction);

	/**
	 * Creates a string instance of the currently collected detailed information
	 * and closes all output streams. You cannot dump further information after
	 * this method was invoked.
	 * 
	 * @return All dumped detailed assembly instruction information.
	 * @throws Exception
	 *             If any error occurs.
	 */
	public String getInstructionDetailsAndClose() throws Exception {
		String details = new String(outputStream.toByteArray(), "UTF-8").trim();
		output.close();
		outputStream.close();

		return details;
	}

	/**
	 * Obtains detailed assembly information of the disassembly contained by the
	 * dumper implementation.
	 * 
	 * @param dumper
	 *            Responsible for dumping of detailed disassembly information.
	 * @return A dump of the assembler commands and information about their
	 *         occupied total bytes and affected registers etc.
	 * @throws Exception
	 *             If any error occurs.
	 */
	public static String createDisassemblyDetails(AssemblyDetailDumper dumper) throws Exception {
		for (CsInsn asm : dumper.disassembly) {
			dumper.printInstructionDetails(asm);
		}

		final String details= dumper.getInstructionDetailsAndClose();
		System.out.println(details);
		
		return details;
	}
}
