package br.unb.unbiquitous.ubiquitos.authentication;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
   
 /** 
  * Class used to encrypt/ decrypt messages and to generate keys.
  * 
  */  


public class Cipher {  
   
	KeyGenerator kgen;
	byte[] raw;
	SecretKey skey;
	javax.crypto.Cipher cipher;
	
    /** 
     * Class constructor. Creates a new instance of KeyGenerator, using AES algoritm and use this 
     * KeyGenerator to create a new key (random number)
     * 
     * @param s - the input key   
     * */
	public Cipher(String password){
		try{
			
			System.out.println("*** password: "+password);
			
			// creates a new instance of KeyGenerator
			kgen = KeyGenerator.getInstance("AES");
			// creates a new instance of SecureRandom
			SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");  
			sr.setSeed(password.getBytes());  
			kgen.init(128, sr);
			skey = kgen.generateKey();  
			raw = toByte(password);
			cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
		} catch (NoSuchAlgorithmException e){
			Logger.getLogger(Cipher.class.getName()).log(Level.SEVERE, null, e);
		} catch (NoSuchPaddingException e) {
			Logger.getLogger(Cipher.class.getName()).log(Level.SEVERE, null, e);
		}
	}

    /** 
     * Class constructor. Creates a new instance of KeyGenerator, using AES algoritm and use this 
     * KeyGenerator to create a new key (random number)
     * 
     * @param s - the input key   
     * */
	public Cipher() {
        try {
        	// creates a new instance of KeyGenerator
            kgen = KeyGenerator.getInstance("AES");

            cipher = javax.crypto.Cipher.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            Logger.getLogger(Cipher.class.getName()).log(Level.SEVERE, null, e);
        } catch (NoSuchPaddingException e) {
        	Logger.getLogger(Cipher.class.getName()).log(Level.SEVERE, null, e);
		}
        kgen.init(128);
        skey = kgen.generateKey();
        raw = skey.getEncoded();
    }

	
    /** 
     * Returns the attribute "raw".
     * 
     * @return raw
     * */
    public byte[] getRaw() throws Exception {  
        return raw;  
    }  

	
	/** 
	 * Encrypts a String and return other String with encoded text.
	 * 
	 * @param plaintext - text to be encrypted
	 * @return toHex(encrypted) - String with encrypted text
	 * */
    public String encrypt(String plaintext) throws Exception {  
        byte[] encrypted = encrypt(plaintext.getBytes());  
        return toHex(encrypted);  
    }  

    
    /** 
	 * Decrypts a String and return other String with decoded text.
	 * 
	 * @param encrypted - encrypted text to be decrypted
	 * @return decrypted - String witch value was returned by encrypt(byte[])
	 * */
    public String decrypt(String encrypted) throws Exception {    
    	
        byte[] str_enc = toByte(encrypted);  
        byte[] decrypted = decrypt(str_enc);  
        System.out.println(" *** decrypted: " + new String(decrypted));
        return new String(decrypted);  
    }  

    
// cipher    
    /** 
	 * Encrypt an array of bytes and return another array of bytes, with the result
	 * of encryption.
	 * 
	 * @param plaintextbyte - array of bytes witch content is the text to be encrypted
	 * @return encrypted - array of bytes with the result of encryption.
	 * */
    public byte[] encrypt(byte[] plaintextbyte) throws Exception {  
        SecretKeySpec skeySpec = new SecretKeySpec(raw, 0, raw.length, "AES");  
        
        byte[] plaintextAndLength = new byte[plaintextbyte.length + 2];
        
        plaintextAndLength[0] = (byte)(0xff & (plaintextbyte.length >> 8));
        plaintextAndLength[1] = (byte)(0xff & plaintextbyte.length);
        
        // build the new plaintext
        System.arraycopy(plaintextbyte, 0, plaintextAndLength, 2, plaintextbyte.length);   

        // calculate the size of the ciperthext considering
        // the padding
        int blocksize = 16;
        int ciphertextLength = 0;
        int remainder = plaintextAndLength.length % blocksize;
        if (remainder == 0) {
          ciphertextLength = plaintextAndLength.length + 16;
        } else {
          ciphertextLength = plaintextAndLength.length - remainder + blocksize;
        }
        
        byte[] plaintextAndLengthWithPadding = new byte[ciphertextLength];
        System.arraycopy(plaintextAndLength, 0, plaintextAndLengthWithPadding, 0, plaintextAndLength.length);
        
        for (int i = plaintextAndLength.length; i < plaintextAndLengthWithPadding.length; i++){
        	plaintextAndLengthWithPadding[i] = 0;
        }
        
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, skeySpec);
        
        byte[] cipherText = new byte[ciphertextLength];
        cipher.doFinal(plaintextAndLengthWithPadding, 0, plaintextAndLengthWithPadding.length-1, cipherText, 0);
        
        return cipherText;  
    }  

    
    /** 
	 * Decrypt an array of bytes and return another array of bytes, with the result
	 * of decryption.
	 * 
	 * @param encryptedBytes - array of bytes witch content is encrypted text
	 * @return encrypted - array of bytes with the result of decryption.
	 * */
    public byte[] decrypt(byte[] encryptedBytes) throws Exception {  
    	
        SecretKeySpec skeySpec = new SecretKeySpec(raw, 0, raw.length, "AES");  

        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, skeySpec);
        byte[] decrypted = new byte[encryptedBytes.length];
        
        // Decrypt the cipher text
        cipher.doFinal(encryptedBytes, 0, encryptedBytes.length, decrypted, 0);
        
        // Calculate the length of the plaintext
        int plainTextLength = (decrypted[0] << 8)  | (decrypted[1] & 0xff);
                
        byte[] finalText = new byte[plainTextLength];
        
        // Decode the final text
        System.arraycopy(decrypted, 2, finalText, 0, plainTextLength);
        
        System.out.println("final text: "+finalText);
        
        return finalText;
    }  

    
// Codec    
//	// Encrypt text with given AES key. It encodes the message
//	// including the length in two bytes and the plaintext
//	public byte[] encrypt (byte[] plaintext)
//	throws InvalidKeySpecException, InvalidKeyException,
//	IllegalStateException, ShortBufferException,
//	IllegalBlockSizeException, BadPaddingException,
//	InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException
//	{
//			javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
//			
//			// Initialize the key from  the password
//			Key key = new SecretKeySpec(raw, 0, raw.length, "AES");
//			// add 2 bytes to encode the length of the plaintext
//			// as a short value
//			byte[] plaintextAndLength = new byte[plaintext.length + 2];
//			plaintextAndLength[0] = (byte)(0xff & (plaintext.length >> 8));
//			plaintextAndLength[1] = (byte)(0xff & plaintext.length);
//			// build the new plaintext
//			System.arraycopy(plaintext, 0, plaintextAndLength, 2, plaintext.length);   
//
//			
//			// calculate the size of the ciperthext considering
//			// the padding
//			int blocksize = 16;
//			int ciphertextLength = 0;
//			int remainder = plaintextAndLength.length % blocksize;
//			if (remainder == 0) {
//				ciphertextLength = plaintextAndLength.length;
//			} else {
//				ciphertextLength = plaintextAndLength.length - remainder
//				+ blocksize;
//			}
//			
//			byte[] cipherText = new byte[ciphertextLength];
//
//			// reinitialize the cipher in encryption mode with the given key
//			cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
//			// do the encryption
//			cipher.doFinal(plaintextAndLength, 0, plaintextAndLength.length, cipherText, 0);
//
//			return cipherText;
//	}
//    
//    
//	// Decrypt text with given AES key. It decodes the message
//	// reading the message length and then the message itself
//	public byte[] decrypt (byte[] cipherText)
//	throws InvalidKeySpecException, InvalidKeyException,
//	IllegalStateException, ShortBufferException,
//	IllegalBlockSizeException, BadPaddingException,
//	InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException
//	{
//			javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
//		
//			// create a key from the keyBits
//			Key key = new SecretKeySpec(raw, 0, raw.length, "AES");
//
//			// Initialize the cipher in decrypt mode
//			cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key);
//
//			byte[] decrypted = new byte[cipherText.length];
//			// Decrypt the cipher text
//			cipher.doFinal(cipherText, 0, cipherText.length, decrypted, 0);
//			// Calculate the length of the plaintext
//			int plainTextLength = (decrypted[0] << 8)  |
//			(decrypted[1] & 0xff);
//			byte[] finalText = new byte[plainTextLength];
//			// Decode the final text
//			System.arraycopy(decrypted, 2, finalText, 0, plainTextLength);
//
//			return finalText;
//	}
    
    
    /** 
     * Receives an array of bytes and returns a String with its hexadecimal value.
     * 
     * @param buffer - the array whose vector is returned
     * @return result - the hexadecimal value
     * */
    public String toHex(byte[] buffer) {  
        if (buffer == null)  
            return "";  
        StringBuffer result = new StringBuffer(2*buffer.length);  
        for (int i = 0; i < buffer.length; i++) {  
            appendHex(result, buffer[i]);  
        }  
        return result.toString();  
    }  
   
    
    /** 
     * Performs the inverse operation of toHex. Receives a String with an hexadecimal 
     * value and returns an array of bytes representing this value.
     * 
     * @param hexString - the String containing the value
     * @return result - the array returned
     * */
    public byte[] toByte(String hexString) {  
        int len = hexString.length()/2;  
        byte[] result = new byte[len];  
        for (int i = 0; i < len; i++)  
            result[i] = Integer.valueOf(hexString.substring(2*i, 2*i+2), 16).byteValue();  
        return result;  
    }
    
    
    /** 
     * Receives a StringBuffer and a byte and append a value to strbuffer. This value
     * is the position of the byte in the constant "0123456789ABCDEF". 
     * */
    private void appendHex(StringBuffer strbuffer, byte b) {
    	final String HEX = "0123456789ABCDEF";
    	strbuffer.append(HEX.charAt((b>>4)&0x0f)).append(HEX.charAt(b&0x0f));  
    }  
    
}  