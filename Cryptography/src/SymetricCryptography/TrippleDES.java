package SymetricCryptography;

public class TrippleDES {
	
	public static String EEE3(String bloc, String key1, String key2, String key3) throws Exception{
		String cipherText = DES.encrypt(bloc, key1);
		cipherText = DES.encrypt(cipherText, key2);
		cipherText = DES.encrypt(cipherText, key3);
		return cipherText;
	}
	
	public static String EDE3(String bloc, String key1, String key2, String Key3) throws Exception{
		// Not yet
		
		return "";
	}
	
	public static String EEE2(String bloc, String key1, String key2) throws Exception{
		String cipherText = DES.encrypt(bloc, key1);
		cipherText = DES.encrypt(cipherText, key2);
		cipherText = DES.encrypt(cipherText, key1);
		return cipherText;
	}
	
	public static String EDE2(String bloc, String key1, String key2) throws Exception{
		// Not yet
		
		return "";
	}
}
