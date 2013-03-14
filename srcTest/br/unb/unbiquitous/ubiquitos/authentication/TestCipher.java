package br.unb.unbiquitous.ubiquitos.authentication;

import junit.framework.TestCase;

public class TestCipher extends TestCase {

	public void testChirpher1() throws Exception {

		String key = "5f8d93682477592c1479ee7803ac44e1";
		
		Cipher c = new Cipher(key);
		
		byte[] plaintext = {1,2,3,4,5}; 
		byte[] encrypted = c.encrypt(plaintext);
		
		byte[] decrypted = c.decrypt(encrypted);
		System.out.println("decrypted: "+decrypted);
		
		for (int i = 0; i < decrypted.length; i++){
			System.out.println(decrypted[i]);
		}
	}

	
	public void testChirpher2() throws Exception {

		String key = "5f8d93682477592c1479ee7803ac44e1";
		
		Cipher c = new Cipher(key);
		
		String plaintext = "12345"; 
		String encrypted = c.encrypt(plaintext);
		
		String decrypted = c.decrypt(encrypted);
		System.out.println("decrypted: "+decrypted);
		
	}

	
	public void testInt() throws Exception {

		byte[] array1 = new byte[10];
		int tamanho = 5432;
		
		array1[0] = (byte)(0xff & (tamanho >> 8));
        array1[1] = (byte)(0xff & tamanho);

        int tamanhoRecuperado = 0;
        tamanhoRecuperado = ((array1[0] << 8)) | ((array1[1]));
        
        System.out.println("tamanhoRecuperado: "+tamanhoRecuperado);
				
        
        byte[] plaintextAndLength = new byte[10];
        plaintextAndLength[0] = (byte)(0xff & (tamanho >> 8));
        plaintextAndLength[1] = (byte)(0xff & tamanho);
        
        int plainTextLength = (array1[0] << 8)  |
        (array1[1] & 0xff);
        
        System.out.println("plainTextLength: "+plainTextLength);
	}

}
