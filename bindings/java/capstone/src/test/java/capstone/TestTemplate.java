/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013
 * Andreas "PAX" L&uuml;ck <onkelpax-git@yahoo.de>, 2016 */
package capstone;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.TestName;

import capstone.Capstone.CsInsn;

public abstract class TestTemplate {
    @Rule 
    public TestName testMethodName = new TestName();
    
	protected Capstone disassembler;
	
	@Before
	public void beforeMethod(){
		System.out.printf("\n============================ %s.%s =================================\n\n", getClass().getSimpleName(), testMethodName.getMethodName());
	}

	@After
	public void afterMethod() {
		if (disassembler != null)
			disassembler.close();

		disassembler = null;
	}

	static public String stringToHex(byte[] code) {
		StringBuilder buf = new StringBuilder(200);
		for (byte ch : code) {
			if (buf.length() > 0)
				buf.append(' ');
			buf.append(String.format("0x%02x", ch));
		}
		return buf.toString();
	}

	static byte[] hexString2Byte(String s) {
		// from
		// http://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	static String hex(int i) {
		return Integer.toString(i, 16);
	}

	static String hex(long i) {
		return Long.toString(i, 16);
	}

	static String array2hex(byte[] arr) {
		String ret = "";
		for (int i = 0; i < arr.length; i++)
			ret += String.format("0x%02x ", arr[i]);
		return ret;
	}

	protected CsInsn[] createDisassembler(int architecture, int mode, byte[] opcodes) {
		return createDisassembler(architecture, mode, 0, opcodes);
	}

	protected CsInsn[] createDisassembler(int architecture, int mode, int syntax, byte[] opcodes) {
		disassembler = new Capstone(architecture, mode);
		disassembler.setDetail(Capstone.CS_OPT_ON);
		if (syntax != 0) {
			disassembler.setSyntax(syntax);
		}

		return disassembler.disasm(opcodes, 0x1000);
	}

	protected void assertDisassembly(String expectedDisassemblyResPath, String givenDisassembly) throws Exception {
		Path resFilePath = Paths.get(getClass().getResource(expectedDisassemblyResPath).toURI());
		String expectedDisassembly = new String(Files.readAllBytes(resFilePath), "UTF-8");

		assertThat(givenDisassembly.replace("\r\n", "\n")).isEqualTo(expectedDisassembly.replace("\r\n", "\n"));
	}
}
