/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013
 * Andreas "PAX" L&uuml;ck <onkelpax-git@yahoo.de>, 2016 */
package capstone;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.After;

import capstone.Capstone.CsInsn;

public abstract class TestTemplate {
	public static class platform {
		public int arch;
		public int mode;
		public int syntax;
		public byte[] code;
		public String comment;

		public platform(int a, int m, int syt, byte[] c, String s) {
			arch = a;
			mode = m;
			code = c;
			comment = s;
			syntax = syt;
		}

		public platform(int a, int m, byte[] c, String s) {
			arch = a;
			mode = m;
			code = c;
			comment = s;
		}
	};

	public static final byte[] PPC_CODE = new byte[] { (byte) 0x80, (byte) 0x20, (byte) 0x00, (byte) 0x00, (byte) 0x80,
			(byte) 0x3f, (byte) 0x00, (byte) 0x00, (byte) 0x10, (byte) 0x43, (byte) 0x23, (byte) 0x0e, (byte) 0xd0,
			(byte) 0x44, (byte) 0x00, (byte) 0x80, (byte) 0x4c, (byte) 0x43, (byte) 0x22, (byte) 0x02, (byte) 0x2d,
			(byte) 0x03, (byte) 0x00, (byte) 0x80, (byte) 0x7c, (byte) 0x43, (byte) 0x20, (byte) 0x14, (byte) 0x7c,
			(byte) 0x43, (byte) 0x20, (byte) 0x93, (byte) 0x4f, (byte) 0x20, (byte) 0x00, (byte) 0x21, (byte) 0x4c,
			(byte) 0xc8, (byte) 0x00, (byte) 0x21 };
	public static final byte[] X86_CODE = new byte[] { (byte) 0x8d, (byte) 0x4c, (byte) 0x32, (byte) 0x08, (byte) 0x01,
			(byte) 0xd8, (byte) 0x81, (byte) 0xc6, (byte) 0x34, (byte) 0x12, (byte) 0x00, (byte) 0x00 };
	public static final byte[] SPARC_CODE = new byte[] { (byte) 0x80, (byte) 0xa0, (byte) 0x40, (byte) 0x02,
			(byte) 0x85, (byte) 0xc2, (byte) 0x60, (byte) 0x08, (byte) 0x85, (byte) 0xe8, (byte) 0x20, (byte) 0x01,
			(byte) 0x81, (byte) 0xe8, (byte) 0x00, (byte) 0x00, (byte) 0x90, (byte) 0x10, (byte) 0x20, (byte) 0x01,
			(byte) 0xd5, (byte) 0xf6, (byte) 0x10, (byte) 0x16, (byte) 0x21, (byte) 0x00, (byte) 0x00, (byte) 0x0a,
			(byte) 0x86, (byte) 0x00, (byte) 0x40, (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x12, (byte) 0xbf, (byte) 0xff, (byte) 0xff, (byte) 0x10, (byte) 0xbf, (byte) 0xff, (byte) 0xff,
			(byte) 0xa0, (byte) 0x02, (byte) 0x00, (byte) 0x09, (byte) 0x0d, (byte) 0xbf, (byte) 0xff, (byte) 0xff,
			(byte) 0xd4, (byte) 0x20, (byte) 0x60, (byte) 0x00, (byte) 0xd4, (byte) 0x4e, (byte) 0x00, (byte) 0x16,
			(byte) 0x2a, (byte) 0xc2, (byte) 0x80, (byte) 0x03 };
	public static final byte[] SYSZ_CODE = new byte[] { (byte) 0xed, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x1a, (byte) 0x5a, (byte) 0x0f, (byte) 0x1f, (byte) 0xff, (byte) 0xc2, (byte) 0x09, (byte) 0x80,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x07, (byte) 0xf7, (byte) 0xeb, (byte) 0x2a, (byte) 0xff,
			(byte) 0xff, (byte) 0x7f, (byte) 0x57, (byte) 0xe3, (byte) 0x01, (byte) 0xff, (byte) 0xff, (byte) 0x7f,
			(byte) 0x57, (byte) 0xeb, (byte) 0x00, (byte) 0xf0, (byte) 0x00, (byte) 0x00, (byte) 0x24, (byte) 0xb2,
			(byte) 0x4f, (byte) 0x00, (byte) 0x78 };
	public static final byte[] SPARCV9_CODE = new byte[] { (byte) 0x81, (byte) 0xa8, (byte) 0x0a, (byte) 0x24,
			(byte) 0x89, (byte) 0xa0, (byte) 0x10, (byte) 0x20, (byte) 0x89, (byte) 0xa0, (byte) 0x1a, (byte) 0x60,
			(byte) 0x89, (byte) 0xa0, (byte) 0x00, (byte) 0xe0 };
	public static final byte[] XCORE_CODE = new byte[] { (byte) 0xfe, (byte) 0x0f, (byte) 0xfe, (byte) 0x17,
			(byte) 0x13, (byte) 0x17, (byte) 0xc6, (byte) 0xfe, (byte) 0xec, (byte) 0x17, (byte) 0x97, (byte) 0xf8,
			(byte) 0xec, (byte) 0x4f, (byte) 0x1f, (byte) 0xfd, (byte) 0xec, (byte) 0x37, (byte) 0x07, (byte) 0xf2,
			(byte) 0x45, (byte) 0x5b, (byte) 0xf9, (byte) 0xfa, (byte) 0x02, (byte) 0x06, (byte) 0x1b, (byte) 0x10 };

	protected Capstone disassembler;

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
