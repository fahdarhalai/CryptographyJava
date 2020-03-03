package ClassicCiphers;

import java.util.HashMap;
import java.util.regex.Pattern;

public class Caesar {
	
	static char[] alphabets = new char[26];
	private int shift; //Shift to left in alphabets
	
	static {
		for(int i=0; i<26; i++) {
			alphabets[i] = (char)(65+i);
		}
	}
	
	public Caesar() {
		shift = 3; // Default
	}
	
	public Caesar(int shift) {
		this.shift = shift;
	}

	public int getShift() {
		return shift;
	}

	public void setShift(int shift) throws Exception {
		if(shift < 0 && shift > 25) {
			throw new Exception("Invalid shift value");
		}
		this.shift = shift;
	}
	
	public void config(int shift) throws Exception {
		setShift(shift);
	}
	
	public String encrypt(String text) {
		return encrypt(text, shift);
	}
	
	public static String encrypt(String text, int shift) {
		StringBuffer cipherText = new StringBuffer();
		String regex = "[a-zA-Z]";
		
		for(int i=0; i<text.length(); i++) {
			if(Pattern.matches(regex, String.valueOf(text.charAt(i)))) {
				int d;
				if(Character.isUpperCase(text.charAt(i))) {
					d = 65;
				}else {
					d = 97;
				}
				int x = (int)text.charAt(i) - d;
				int c = (x+shift)%26 + d;
				
				cipherText.append((char)c);
			}else {
				cipherText.append(text.charAt(i));
			}
		}
		
		return cipherText.toString();
	}
	
	public String decrypt(String text) {
		return decrypt(text, this.shift);
	}
	
	public static String decrypt(String text, int shift) {
		StringBuffer plainText = new StringBuffer();
		String regex = "[a-zA-Z]";
		
		for(int i=0; i<text.length(); i++) {
			if(Pattern.matches(regex, String.valueOf(text.charAt(i)))) {
				int d;
				if(Character.isUpperCase(text.charAt(i))) {
					d = 65;
				}else {
					d = 97;
				}
				int c = (int)text.charAt(i) - d;
				int x = (c-shift+26)%26 + d;
				
				plainText.append((char)x);
			}else {
				plainText.append(text.charAt(i));
			}
		}
		
		return plainText.toString();
	}
	
	enum Language{
		FR, EN;
	}
	
	public static class FrequencyAnalyser{
		
		static Language lang = Language.EN;
		
		private static HashMap<Character, Integer> getHashMap(String text){
			HashMap<Character,Integer> map = new HashMap<>();
			for(char c : text.toCharArray()) {
				if(map.containsKey(Character.toLowerCase(c)) || map.containsKey(Character.toUpperCase(c))) {
					map.put(Character.toUpperCase(c), map.get(Character.toUpperCase(c))+1);
				}else if(Pattern.matches("[a-zA-Z]", String.valueOf(c))) {
					map.put(Character.toUpperCase(c), 0);
				}
			}
			
			return map;
		}
		
		private static char getMostFrequentChar(HashMap<Character, Integer> map) {
			int max = 0;
			char ch = ' ';
			
			for(Character c : map.keySet()) {
				if(max < map.get(c)) {
					max = map.get(c);
					ch = c;
				}
			}
			
			return ch;
		}
		
		public static int findShift(String text) {
			
			HashMap<Character,Integer> map = getHashMap(text);
			char c = getMostFrequentChar(map);
			char mostFreqChar;
			switch (FrequencyAnalyser.lang) {
			
			case EN:
				mostFreqChar = 'E';
				break;
			case FR:
				mostFreqChar = 'E';
				break;
			default:
				mostFreqChar = 'E';
				break;
			}
			
			int myShift = ((int)c - (int)mostFreqChar + 26)%26;
			
			return myShift;
		}
		
		public static String decrypt(String text) {
			StringBuffer plainText = new StringBuffer();
			int myShift = findShift(text);
			
			for(int i=0; i<text.length(); i++) {
				if(Pattern.matches("[a-zA-Z]", String.valueOf(text.charAt(i)))) {
	
					int d;
					
					if(Character.isUpperCase(text.charAt(i))) {
						d = 65;
					}else {
						d = 97;
					}
					
					int c = (int)text.charAt(i) - d;
					int x = (c - myShift + 26)%26 + d;
					
					plainText.append((char)x);
				}else {
					plainText.append(text.charAt(i));
				}
				
			}
			
			return plainText.toString();
		}
		
	}
	
	
}
