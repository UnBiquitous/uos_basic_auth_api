package br.unb.unbiquitous.ubiquitos.authentication;

import junit.framework.TestCase;

public class TestHMAC extends TestCase {

	
	public void testSuccessfulAuthentication() throws Exception {
				
		String key = "5f8d93682477592c1479ee7803ac44e1";
		String ra1 = "87526612321260";
		
		Cipher cipher = new Cipher(key);
		String ra1Enc = cipher.encrypt(ra1);
		System.out.println("ra1Enc: "+ra1Enc);
		
		String ra1Dec = cipher.decrypt(ra1Enc);
		System.out.println("ra1Dec: "+ra1Dec);
		
		char c = ' '-1;
		System.out.println((Character.forDigit((char)(c & 0x0f), 16)));
		c = '+';
		System.out.println((Character.forDigit((char)(c & 0x0f), 16)));
		c = '%';
		System.out.println((Character.forDigit((char)(c & 0x0f), 16)));
		c = '=';
		System.out.println((Character.forDigit((char)(c & 0x0f), 16)));
		c = ';';
		System.out.println((Character.forDigit((char)(c & 0x0f), 16)));

		System.out.println();
		System.out.println();
		c = '%';
		System.out.println("tentativa 1:");
		System.out.printf("%s\n",(char)(c & 0x0f));
		System.out.println();
		System.out.println();
		
		c = ' '-1;
		if (c < 10){
			System.out.printf("%s\n", Character.digit('0'+c, 16));
		} else{
			System.out.printf("%s\n", Character.digit('a'+c-10, 16));
		}
		
		c = '+';
		if (c < 10){
			System.out.printf("%s\n", Character.digit('0'+c, 16));
		} else{
			System.out.printf("%s\n", Character.digit('a'+c-10, 16));
		}
		
		c = '%';
		if (c < 10){
			System.out.printf("%s", '0'+c);
		} else{
			System.out.printf("%s", 'a'+c-10);
		}
		
		c = '=';
		if (c < 10){
			System.out.printf("%s", '0'+c);
		} else{
			System.out.printf("%s", 'a'+c-10);
		}
		
		c = ';';
		if (c < 10){
			System.out.printf("%s", '0'+c);
		} else{
			System.out.printf("%s", 'a'+c-10);
		}
	}
}
