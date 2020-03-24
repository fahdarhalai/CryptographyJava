package SymmetricCryptography;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.regex.Pattern;

import javax.xml.bind.DatatypeConverter;

public class DES {
	public static enum Algorithm{
		ECB,
		CBC
	}
	
	static int[] initialPerm = { 58, 50, 42, 34, 26, 18, 10, 2, 
					            60, 52, 44, 36, 28, 20, 12, 4, 
					            62, 54, 46, 38, 30, 22, 14, 6, 
					            64, 56, 48, 40, 32, 24, 16, 8, 
					            57, 49, 41, 33, 25, 17, 9, 1, 
					            59, 51, 43, 35, 27, 19, 11, 3, 
					            61, 53, 45, 37, 29, 21, 13, 5, 
					            63, 55, 47, 39, 31, 23, 15, 7 };
	
	static int[] initialPermInverse = { 40, 8, 48, 16, 56, 24, 64, 32, 
							            39, 7, 47, 15, 55, 23, 63, 31, 
							            38, 6, 46, 14, 54, 22, 62, 30, 
							            37, 5, 45, 13, 53, 21, 61, 29, 
							            36, 4, 44, 12, 52, 20, 60, 28, 
							            35, 3, 43, 11, 51, 19, 59, 27, 
							            34, 2, 42, 10, 50, 18, 58, 26, 
							            33, 1, 41, 9, 49, 17, 57, 25 };
	
	static int[][] sBox = { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 
					        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 
					        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 
					        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }, 
					      { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 
					        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 
					        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 
					        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
					      { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 
					        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 
					        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 
					        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }, 
					      { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 
					        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 
					        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 
					        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }, 
					      { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 
					        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 
					        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 
					        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }, 
					      { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 
					        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 
					        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 
					        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }, 
					      { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 
					        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 
					        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 
					        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }, 
					      { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 
					        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 
					        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 
					        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };
	
	static int[] blocPerm = { 16, 7, 20, 21, 
				            29, 12, 28, 17, 
				            1, 15, 23, 26, 
				            5, 18, 31, 10, 
				            2, 8, 24, 14, 
				            32, 27, 3, 9, 
				            19, 13, 30, 6, 
				            22, 11, 4, 25 };
	
	static String IV = "0101010101010101010101010101010101010101010101010101010101010101";
	
	public static class Converter{
		
		static String stringToHex(String text) throws UnsupportedEncodingException {
			return String.format("%x", new BigInteger(1, text.getBytes("UTF-8")));
		}
		
		static String hexToString(String hex) throws UnsupportedEncodingException {
			byte[] bytes = DatatypeConverter.parseHexBinary(hex);
			return new String(bytes, "UTF-8");
		}
		
		static String hexToBinary(String hex) {
			return new BigInteger(hex, 16).toString(2);
		}
		
		static String binaryToHex(String bin) {
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
		
		static int binaryToInteger(String binary) {
		    char[] numbers = binary.toCharArray();
		    int result = 0;
		    for(int i=numbers.length - 1; i>=0; i--)
		        if(numbers[i]=='1')
		            result += Math.pow(2, (numbers.length-i - 1));
		    return result;
		}
		
	}
	
	static class KeyGenerator{
		//Key Parity Drop with permutation 
		static int[] PC1 = { 57, 49, 41, 33, 25, 17, 9, 
				            1, 58, 50, 42, 34, 26, 18, 
				            10, 2, 59, 51, 43, 35, 27, 
				            19, 11, 3, 60, 52, 44, 36, 
				            63, 55, 47, 39, 31, 23, 15, 
				            7, 62, 54, 46, 38, 30, 22, 
				            14, 6, 61, 53, 45, 37, 29, 
				            21, 13, 5, 28, 20, 12, 4 };
		
		//Key compression 56->48 bits
		static int[] PC2 = { 14, 17, 11, 24, 1, 5, 
				            3, 28, 15, 6, 21, 10, 
				            23, 19, 12, 4, 26, 8, 
				            16, 7, 27, 20, 13, 2, 
				            41, 52, 31, 37, 47, 55, 
				            30, 40, 51, 45, 33, 48, 
				            44, 49, 39, 56, 34, 53, 
				            46, 42, 50, 36, 29, 32 };
		
		//Number of key bits shifted per round
		static int[] LS = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
		
		static String dropParity(String key) throws Exception {
			if(key.length() != 64) throw new Exception("Key must be 64-bits of length");
			
			StringBuffer newKey = new StringBuffer();
			
			for(int i=0; i<PC1.length; i++) {
				int index = PC1[i];
				newKey.append(key.charAt(index-1));
			}
			
			return newKey.toString();
		}
		
		static String[] splitInHalf(String key) throws Exception {
			String[] CD = new String[2];
			
			if(key.length() != 56) throw new Exception("Key must be 56-bits of length");
			
			CD[0] = key.substring(0, 28);
			CD[1] = key.substring(28, 56);
			
			return CD;
		}
		
		static String leftShiftKey(String half, int round) {
			int shift = LS[round];
			
			StringBuffer newHalf = new StringBuffer();
			for(int i=0; i<shift; i++) {
				newHalf.append(half.substring(1));
				newHalf.append(half.charAt(0));
				half = newHalf.toString();
				newHalf.delete(0, 28);
			}
			return half;
		}
		
		static String rightShiftKey(String half, int round) {
			int shift = LS[round];
			
			StringBuffer newHalf = new StringBuffer();
			for(int i=0; i<shift; i++) {
				newHalf.append(half.charAt(27));
				newHalf.append(half.substring(0, 27));
				half = newHalf.toString();
				newHalf.delete(0, 28);
			}
			return half;
		}
		
		static String groupKey(String C, String D) {
			return C+D;
		}
		
		static String compressKey(String key) throws Exception {
			if(key.length() != 56) throw new Exception("Key must be 56-bits of length");
			
			StringBuffer newKey = new StringBuffer();
			
			for(int i=0; i<PC2.length; i++) {
				int index = PC2[i];
				
				newKey.append(key.charAt(index-1));
			}
			
			return newKey.toString();
		}
		
		static String[] getRoundKeyLeft(String key, int round) throws Exception {
			if(key.length() != 56) throw new Exception("Key must be 56-bits of length");
			
			String[] CD = splitInHalf(key);
			String s1 = leftShiftKey(CD[0], round);
			String s2 = leftShiftKey(CD[1], round);
			String s = groupKey(s1, s2);
			
			key = s;
			
			String[] res = new String[2];
			res[0] = key;
			res[1] = compressKey(s);
			return res;
		}
		
		static String[] getRoundKeyRight(String key, int round) throws Exception {
			if(key.length() != 56) throw new Exception("Key must be 56-bits of length");
			
			String[] CD = splitInHalf(key);
			String s1 = rightShiftKey(CD[0], round);
			String s2 = rightShiftKey(CD[1], round);
			String s = groupKey(s1, s2);
			
			String[] res = new String[2];
			res[0] = s;
			res[1] = compressKey(s);
			return res;
		}
		
	}
	 
	static String permute(String bloc) throws Exception{
		if(bloc.length() != 64) throw new Exception("Bloc must be 64-bits of length");
		
		StringBuffer newBloc = new StringBuffer();
		
		for(int i=0; i<initialPerm.length; i++) {
			int index = initialPerm[i];
			
			newBloc.append(bloc.charAt(index-1));
		}
		
		return newBloc.toString();
	}
	
	static String permuteInverse(String bloc) throws Exception{
		if(bloc.length() != 64) throw new Exception("Bloc must be 64-bits of length");
		
		StringBuffer newBloc = new StringBuffer();
		
		for(int i=0; i<initialPermInverse.length; i++) {
			int index = initialPermInverse[i];
			
			newBloc.append(bloc.charAt(index-1));
		}
		
		return newBloc.toString();
	}
	
	static String XOR(String L, String R) throws Exception {
		if(L.length() != R.length()) throw new Exception("Operands must be of the same length");
		StringBuffer result = new StringBuffer();
		
		for(int i=0; i<L.length(); i++) {
			result.append(L.charAt(i)^R.charAt(i));
		}
		
		return result.toString();
	}
	
	static String[] splitInHalf(String bloc) throws Exception {
		if(bloc.length() != 64) throw new Exception("Bloc must be 64-bits of length");
		
		String[] LR = new String[2];
		
		LR[0] = bloc.substring(0, 32);
		LR[1] = bloc.substring(32, 64);
		
		return LR;
	}
	
	static String groupBloc(String L, String R) {
		return L + R;
	}
	
	static String encryptFct(String bloc, String key) throws Exception {
		if(bloc.length() != 32) throw new Exception("Bloc must be 32-bits of length");
		if(key.length() != 48) throw new Exception("Key must be 48-bits of length");
		
		String expBloc = expandBloc(bloc);
		String xorBloc = XOR(expBloc, key);
		String subBloc = substituteBloc(xorBloc);
		String finalBloc = permuteBloc(subBloc);
		
		return finalBloc;
	}
	
	static String expandBloc(String bloc) throws Exception {
		if(bloc.length() != 32) throw new Exception("Bloc must be 32-bits of length");
		StringBuffer newBloc = new StringBuffer();
		for(int i=0; i<32; i=i+4) {
			if(i==0) {
				newBloc.append(bloc.charAt(31));
			}else {
				newBloc.append(bloc.charAt(i-1));
			}
			newBloc.append(bloc.charAt(i));
			newBloc.append(bloc.charAt(i+1));
			newBloc.append(bloc.charAt(i+2));
			newBloc.append(bloc.charAt(i+3));
			if(i==28) {
				newBloc.append(bloc.charAt(0));
			}else {
				newBloc.append(bloc.charAt(i+4));
			}
		}
		
		return newBloc.toString();
	}
	
	static String substitute(String part, int index) throws Exception{
		if(part.length() != 6) throw new Exception("Sub-bloc must be 6-bits of length");
		
		StringBuffer helper = new StringBuffer();
		helper.append(part.charAt(0));
		helper.append(part.charAt(5));
		
		int row = Converter.binaryToInteger(helper.toString());
		int col = Integer.parseInt(part.substring(1,5), 2);
		int res = sBox[index][row*16 + col];
		
		StringBuffer result = new StringBuffer(Integer.toBinaryString(res));
		while(result.length()<4) {
			result.insert(0, "0");
		}
		
		return result.toString();
	}
	
	static String substituteBloc(String bloc) throws Exception{
		if(bloc.length() != 48) throw new Exception("Bloc must be 48-bits of length");
		
		StringBuffer newBloc = new StringBuffer();
		int index = 0;
		
		for(int i=0; i<bloc.length(); i+=6) {
			String part = bloc.substring(i, i+6);
			newBloc.append(substitute(part, index++));
		}
		return newBloc.toString();
	}
	
	static String permuteBloc(String bloc) throws Exception{
		if(bloc.length() != 32) throw new Exception("Bloc must be 32-bits of length");
		
		StringBuffer newBloc = new StringBuffer();
		
		for(int i=0; i<blocPerm.length; i++) {
			int index = blocPerm[i];
			
			newBloc.append(bloc.charAt(index-1));
		}
		
		return newBloc.toString();
	}

	static String encryptRound(String bloc, String key) throws Exception{
		if(bloc.length() != 64) throw new Exception("Bloc must be 64-bits of length");
		if(key.length() != 48) throw new Exception("Key must be 48-bits of length");
		
		String[] LR = splitInHalf(bloc);
		String encrypted = encryptFct(LR[1], key);
		String R = XOR(LR[0], encrypted);
		
		return groupBloc(LR[1], R);
	}
	
	static String decryptRound(String bloc, String key) throws Exception{
		if(bloc.length() != 64) throw new Exception("Bloc must be 64-bits of length");
		if(key.length() != 48) throw new Exception("Key must be 48-bits of length");
		
		String[] LR = splitInHalf(bloc);
		String encrypted = encryptFct(LR[0], key);
		String R = XOR(LR[1], encrypted);
		
		return groupBloc(R, LR[0]);
	}

	static String encrytAllRounds(String bloc, String key) throws Exception{
		if(bloc.length() != 64) throw new Exception("Bloc must be 64-bits of length");
		if(key.length() != 64) throw new Exception("Key must be 64-bits of length");
		
		key = KeyGenerator.dropParity(key);
		String roundKey = "";
		String[] res = new String[2];
		for(int i=0; i<16; i++) {
			res = KeyGenerator.getRoundKeyLeft(key, i);
			key = res[0];
			roundKey = res[1];
			bloc = encryptRound(bloc, roundKey);
		}
		
		return bloc;
	}

	static String decryptAllRounds(String bloc, String key) throws Exception{
		if(bloc.length() != 64) throw new Exception("Bloc must be 64-bits of length");
		if(key.length() != 64) throw new Exception("Key must be 64-bits of length");
		
		key = KeyGenerator.dropParity(key);
		String roundKey = "";
		String[] res = new String[2];
		res = KeyGenerator.getRoundKeyLeft(key, 0);
		key = res[0];
		for(int i=0; i<16; i++) {
			res = KeyGenerator.getRoundKeyRight(key, i);
			key = res[0];
			roundKey = res[1];
			bloc = decryptRound(bloc, roundKey);
		}
		
		return bloc;
	}
	
	static String encrypt(String bloc, String key) throws Exception{
		String myBloc = permute(bloc);

		myBloc = encrytAllRounds(myBloc, key);

		myBloc = permuteInverse(myBloc);
		
		return myBloc;
	}

	static String decrypt(String bloc, String key) throws Exception{
		String myBloc = permute(bloc);

		myBloc = decryptAllRounds(myBloc, key);

		myBloc = permuteInverse(myBloc);
		
		return myBloc;
	}
	
	public static String encrypt(File file, String key, Algorithm algorithm) throws Exception{
		
		try (InputStream stream = new FileInputStream(file)) {
			StringBuffer result = new StringBuffer();
			StringBuffer sb = new StringBuffer();
			
			byte[] array = new byte[8];
			int data = stream.read(array, 0, 8);
			String prev = "";
			
			if(data != -1) {
				for(int i=0; i<8; i++) {
					StringBuffer helper = new StringBuffer(Integer.toBinaryString(array[i]));
					
					while(helper.length() < 8) {
						helper.insert(0, "0");
					}
					sb.append(helper.toString());
				}
				
				for(int i=0; i<8; i++) {
					array[i] = 0;
				}
				
				if(algorithm == Algorithm.ECB) {
					result.append(DES.encrypt(sb.toString(), key));
				}else if(algorithm == Algorithm.CBC) {
					prev = DES.encrypt(XOR(sb.toString(), IV), key);
					result.append(prev);
				}
				
				sb.delete(0, 64);
				data = stream.read(array, 0, 8);
			}
			
			while(data != -1) {
				for(int i=0; i<8; i++) {
					StringBuffer helper = new StringBuffer(Integer.toBinaryString(array[i]));
					
					while(helper.length() < 8) {
						helper.insert(0, "0");
					}
					sb.append(helper.toString());
				}
				
				for(int i=0; i<8; i++) {
					array[i] = 0;
				}
				
				if(algorithm == Algorithm.ECB) {
					result.append(DES.encrypt(sb.toString(), key));
				}else if(algorithm == Algorithm.CBC) {
					prev = DES.encrypt(XOR(sb.toString(), prev),key);
					result.append(prev);
				}
				
				sb.delete(0, 64);
				data = stream.read(array, 0, 8);
			}
			
			return result.toString();
		}
	}
	
	public static String decrypt(File file, String key, Algorithm algorithm) throws Exception{
		try (Reader r = new BufferedReader(new InputStreamReader(new FileInputStream(file)))){
			StringBuffer result = new StringBuffer();
			StringBuffer sb = new StringBuffer();
			String prev = "";
			
			int intChar;
			while((intChar = r.read()) != -1) {
				sb.append((char) intChar);
				if(sb.length() == 64 ) {
					if(algorithm == Algorithm.ECB) {
						result.append(DES.decrypt(sb.toString(), key));
					}else if(algorithm == Algorithm.CBC) {
						prev = sb.toString();
						result.append(XOR(DES.decrypt(sb.toString(), key), IV));
					}
					sb.delete(0, 64);
					break;
				}
			}
			
			while ((intChar = r.read()) != -1) {
				sb.append((char) intChar);
				if(sb.length() == 64 ) {
					if(algorithm == Algorithm.ECB) {
						result.append(DES.decrypt(sb.toString(), key));
					}else if(algorithm == Algorithm.CBC) {
						result.append(XOR(DES.decrypt(sb.toString(), key), prev));
						prev = sb.toString();
					}
					sb.delete(0, 64);
				}
			}
			
			return result.toString();
		}
	}
	
}
