package ClassicCiphers;

import java.util.regex.Pattern;

public class Vigenere {
	
	static char[] alphabets = new char[26];
	private String key;
	
	static {
		for(int i=0; i<26; i++) {
			alphabets[i] = (char)(65+i);
		}
	}
	
	public Vigenere(String key) throws Exception {
		this.setKey(key);
	}

	public String getKey() {
		return key;
	}

	public void setKey(String key) throws Exception {
		String regex = "[a-zA-Z]+";
		if(!Pattern.matches(regex, key)) {
			throw new Exception("Key should be only of alphabets");
		}
		this.key = key.toUpperCase();
	}
	
	public void config(String key) throws Exception {
		setKey(key);
	}
	
	public String encrypt(String text) throws Exception {
		return encrypt(text, key);
	}
	
	public static String encrypt(String text, String key) throws Exception {
		StringBuffer cipherText = new StringBuffer();
		String regex = "[a-zA-Z]+";
		
		if(!Pattern.matches(regex, key)) {
			throw new Exception("Key should be only of alphabets");
		}
		
		key = key.toUpperCase();
		
		for(int i=0; i<text.length(); i++) {
			
			if(Pattern.matches("[a-zA-Z]", String.valueOf(text.charAt(i)))) {
				int k = (int)key.charAt(i%key.length()) - 65;
				int d;
				
				if(Character.isUpperCase(text.charAt(i))) {
					d = 65;
				}else {
					d = 97;
				}
				
				int x = (int)text.charAt(i) - d;
				int c = (x+k)%26 + d;
				
				cipherText.append((char)c);
			}else {
				cipherText.append(text.charAt(i));
			}
			
		}
		
		return cipherText.toString();
	}
	
	public String decrypt(String text) throws Exception {
		return decrypt(text, this.key);
	}
	
	public static String decrypt(String text, String key) throws Exception {
		StringBuffer plainText = new StringBuffer();
		String regex = "[a-zA-Z]+";
		
		if(!Pattern.matches(regex, key)) {
			throw new Exception("Key should be only of alphabets");
		}
		
		key = key.toUpperCase();
		
		for(int i=0; i<text.length(); i++) {
			
			if(Pattern.matches("[a-zA-Z]", String.valueOf(text.charAt(i)))) {
				int k = (int)key.charAt(i%key.length()) - 65;
				int d;
				
				if(Character.isUpperCase(text.charAt(i))) {
					d = 65;
				}else {
					d = 97;
				}
				
				int c = (int)text.charAt(i) - d;
				
				int x = (c-k+26)%26 + d;
				
				plainText.append((char)x);
			}else {
				plainText.append(text.charAt(i));
			}
			
		}
		
		return plainText.toString();
	}
	
	
}
