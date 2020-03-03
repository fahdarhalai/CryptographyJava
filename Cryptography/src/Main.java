import ClassicCiphers.*;

public class Main {
	public static void main(String[] args) throws Exception {
		
		Caesar c = new Caesar();
		
		// Encryption using Caesar cipher
		String cText = c.encrypt("Cryptography or cryptology is the"
				+ " practice and study of techniques for secure"
				+ " communication in the presence of third parties"
				+ " called adversaries.");
		
		// Decryption using the static class FrequencyAnalyser of Caesar class
		String pText = Caesar.FrequencyAnalyser.decrypt(cText);
		
		System.out.println("Cipher Text:\n"+cText);
		System.out.println("------");
		System.out.println("Plain Text:\n"+pText);
		
	}
}
