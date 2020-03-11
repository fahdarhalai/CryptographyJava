
import java.io.File;
import java.io.PrintWriter;

import SymetricCryptography.DES;
import SymetricCryptography.DES.Algorithm;
// Main includes a test of DES (ECB algorithm)
public class Main {
	
	public static void main(String[] args) throws Exception {
		String key = "0001010010011001010101001010010101001001010010100101001010101110";
		String text = "0100100001100101011011000110110001101111010101110110111100110001";
        
        File file = new File("src/plainText.txt");
        
        String cipherText = DES.encrypt(file, key, DES.Algorithm.ECB);
        
        System.out.println(cipherText);
        
        File file2 = new File("src/cipherText.txt");
        PrintWriter out = new PrintWriter(file2);
        
        out.println(DES.Converter.binaryToString(cipherText));
        
        out.close();

        String plainText = DES.decrypt(file2, key, Algorithm.ECB);
//        System.out.println(DES.Converter.binaryToString(cipherText));
        
	}
}
