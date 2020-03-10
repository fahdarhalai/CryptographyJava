import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import SymetricCryptography.DES;
// Main includes a test of DES (ECB algorithm)
public class Main {
	public static void main(String[] args) throws Exception {
		
		File file = new File("src/test.txt");
		String key = "0001010111011010011000010100111010111010010011011101101110001010";
        
        String cipherTextBinary = DES.encrypt(file, key, DES.Algorithm.ECB);
        
        
        System.out.println(cipherTextBinary);
//        System.out.println(DES.Converter.binaryToString(cipherTextBinary));
	}
}
