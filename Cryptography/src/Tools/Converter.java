package Tools;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.regex.Pattern;

import javax.xml.bind.DatatypeConverter;

public class Converter {
	public static String stringToHex(String text) throws UnsupportedEncodingException {
		return String.format("%x", new BigInteger(1, text.getBytes("UTF-8")));
	}
	
	public static String hexToString(String hex) throws UnsupportedEncodingException {
		byte[] bytes = DatatypeConverter.parseHexBinary(hex);
		return new String(bytes, "UTF-8");
	}
	
	public static String hexToBinary(String hex) {
		return new BigInteger(hex, 16).toString(2);
	}
	
	public static String binaryToHex(String bin) {
		return new BigInteger(bin, 2).toString(16).toUpperCase();
	}
	
	public static String stringToBinary(String text) throws UnsupportedEncodingException {
		return hexToBinary(stringToHex(text));
	}
	
	public static String binaryToString(String bin) throws UnsupportedEncodingException {
		if(Pattern.matches("0*", bin)) {
			return "";
		}
		return hexToString(binaryToHex(bin));
	}
	
	public static long binaryToInteger(String binary) {
	    Long result = Long.parseUnsignedLong(binary, 2);
	    return result;
	}
}
