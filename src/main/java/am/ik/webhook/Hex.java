package am.ik.webhook;

class Hex {

	public static String encodeHex(byte[] data) {
		final StringBuilder sb = new StringBuilder();
		for (byte datum : data) {
			sb.append(toHex(datum));
		}
		return sb.toString();
	}

	static String toHex(byte b) {
		final char[] hex = new char[2];
		hex[0] = Character.forDigit((b >> 4) & 0xF, 16);
		hex[1] = Character.forDigit((b & 0xF), 16);
		return new String(hex).toLowerCase();
	}

}
