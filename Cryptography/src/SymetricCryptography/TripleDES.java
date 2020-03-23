package SymetricCryptography;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;

public class TripleDES {
	
	public static enum EncryptMode{
		EEE3,
		EDE3,
		EEE2,
		EDE2
	}
	
	public static enum DecryptMode{
		DDD3,
		DDD2,
		DED3,
		DED2
	}
	
	// Encryption Modes
	private static String EEE3(String bloc, String key1, String key2, String key3) throws Exception{
		return DES.encrypt(DES.encrypt(DES.encrypt(bloc, key1), key2), key3);
	}
	
	private static String EDE3(String bloc, String key1, String key2, String key3) throws Exception{
		return DES.encrypt(DES.decrypt(DES.encrypt(bloc, key1), key2), key3);
	}
	
	private static String EEE2(String bloc, String key1, String key2) throws Exception{
		return DES.encrypt(DES.encrypt(DES.encrypt(bloc, key1), key2), key1);
	}
	
	private static String EDE2(String bloc, String key1, String key2) throws Exception{
		return DES.encrypt(DES.decrypt(DES.encrypt(bloc, key1), key2), key1);
	}
	
	// Decryption Modes
	private static String DDD3(String bloc, String key1, String key2, String key3) throws Exception{
		return DES.decrypt(DES.decrypt(DES.decrypt(bloc, key1), key2), key3);
	}
	
	private static String DED3(String bloc, String key1, String key2, String key3) throws Exception{
		return DES.decrypt(DES.encrypt(DES.decrypt(bloc, key1), key2), key3);
	}
	
	private static String DDD2(String bloc, String key1, String key2) throws Exception{
		return DES.decrypt(DES.decrypt(DES.decrypt(bloc, key1), key2), key1);
	}
	
	private static String DED2(String bloc, String key1, String key2) throws Exception{
		return DES.decrypt(DES.encrypt(DES.decrypt(bloc, key1), key2), key1);
	}
	
	public static String encrypt(File file, String key1, String key2, String key3, EncryptMode mode) throws Exception {
		try (InputStream stream = new FileInputStream(file)) {
			StringBuffer result = new StringBuffer();
			StringBuffer sb = new StringBuffer();
			
			byte[] array = new byte[8];
			int data = stream.read(array, 0, 8);
			
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
				
				if(mode == EncryptMode.EEE3) {
					result.append(EEE3(sb.toString(), key1, key2, key3));
				}else if(mode == EncryptMode.EEE2) {
					result.append(EEE2(sb.toString(), key1, key2));
				}else if(mode == EncryptMode.EDE3) {
					result.append(EDE3(sb.toString(), key1, key2, key3));
				}else if(mode == EncryptMode.EDE2) {
					result.append(EDE2(sb.toString(), key1, key2));
				}
				
				sb.delete(0, 64);
				data = stream.read(array, 0, 8);
			}
			
			return result.toString();
		}
	}
	
	public static String decrypt(File file, String key1, String key2, String key3, DecryptMode mode) throws Exception {
		try (Reader r = new BufferedReader(new InputStreamReader(new FileInputStream(file)))){
			StringBuffer result = new StringBuffer();
			StringBuffer sb = new StringBuffer();
			
			int intChar;
			while ((intChar = r.read()) != -1) {
				sb.append((char) intChar);
				if(sb.length() == 64 ) {

					if(mode == DecryptMode.DDD3) {
						result.append(DDD3(sb.toString(), key1, key2, key3));
					}else if(mode == DecryptMode.DDD2) {
						result.append(DDD2(sb.toString(), key1, key2));
					}else if(mode == DecryptMode.DED3) {
						result.append(DED3(sb.toString(), key1, key2, key3));
					}else if(mode == DecryptMode.DED2) {
						result.append(DED2(sb.toString(), key1, key2));
					}
					
					sb.delete(0, 64);
				}
			}
			
			return result.toString();
		}
	}
}
