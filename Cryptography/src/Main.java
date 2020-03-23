import java.io.File;
import java.io.PrintWriter;
import SymetricCryptography.DES;
import SymetricCryptography.DES.Algorithm;
import SymetricCryptography.TripleDES;
import SymetricCryptography.TripleDES.DecryptMode;
import SymetricCryptography.TripleDES.EncryptMode;

public class Main {
	
	public static void main(String[] args) throws Exception {
		// A random 64-bit key
		String key1 = "1011000001000101101000011010001000100111001010001101111000010011";
		String key2 = "0101100011110011000110000000110000010001010001111110101001011100";
		String key3 = "1101001101010010110011011111110111101000110010000101001010101101";
		
//		  // Encrypting the file plainText.txt 
//        File pFile = new File("src/plainText.txt");
//        String cipherText = DES.encrypt(pFile, key, DES.Algorithm.CBC);
//        
//        // Writing the cipher text into cipherText.txt
//        File cFile = new File("src/cipherText.txt");
//        PrintWriter out = new PrintWriter(cFile);
//        out.println(cipherText);
//        out.close();
//
//        // Decrypting cipherText.txt
//        String plainText = DES.decrypt(cFile, key, Algorithm.CBC);
//        System.out.println(DES.Converter.binaryToString(plainText));
		
		
		File pFile = new File("src/plainText.txt");
		String cipherText = TripleDES.encrypt(pFile, key1, key2, key3, EncryptMode.EEE2);
//		System.out.println(cipherText);
		
		
		// Writing the cipher text into cipherText.txt
		File cFile = new File("src/cipherText.txt");
		PrintWriter out = new PrintWriter(cFile);
		out.println(cipherText);
		out.close();
		
		// Decrypting cipherText.txt
        String plainText = TripleDES.decrypt(cFile, key1, key2, key3, DecryptMode.DDD2);
        System.out.println(DES.Converter.binaryToString(plainText));
        
        
        
	}
}
