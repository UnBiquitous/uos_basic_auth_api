package br.unb.unbiquitous.ubiquitos.authentication;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.DigestException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class HMacUtils{

	private static final Logger logger = Logger.getLogger(HMacUtils.class.getName());
	
    /**
     * Performs XOR operation between two Strings. Converts the Strings to an
     * array of bytes and performs the xor operation in each byte of the arrays.
     */
    public static String stringXor(String strMessage, String strKey) {
        
        String result = null;
        byte[] messageBuf = strMessage.getBytes();
        byte[] keyBuf = strKey.getBytes();
        ByteArrayOutputStream baos = new ByteArrayOutputStream(messageBuf.length);

        int c = 0;

        for (int i = 0; i < messageBuf.length; i++) {
            byte messageByte = messageBuf[i];
            byte keyByte = keyBuf[c];

            //byte xorByte = (byte)(messageByte ^ keyByte);
            byte xorByte = (byte) (messageByte ^ keyByte);

            if (c < keyBuf.length - 1) {
                c++;
            } else {
                c = 0;
            }

            baos.write(xorByte);
        }

        try {
            baos.flush();
            result = baos.toString();
            baos.close();
            baos = null;
        } catch (IOException e) {
            System.out.println("Exception: " + e);
        }

        return result;
    }

	
	/** 
	 * Generates the HMAC of a given message, using a given key.
	 * The formula used to calculate HMAC is:
     * Kmac(key, message) = Hash((key^opad) ++ Hash((key^ipad) ++ message))
     * where ++ denote concatenation and ^ denote exclusive or (xor)
     *
	 * @param hmacKey - the key
	 * @param message - message witch HMAC will be generated
	 * @return code - HMAC(key, message)
	 * @throws DigestException 
	 * */
	public static String generateHMac (String hmacKey, String message) throws DigestException{
		
        //create an array of bytes witch length is 512 bits, the block size in SHA-1
        byte[] opad = {0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                       0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                       0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                       0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                       0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                       0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                       0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                       0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c};

        //create an array of bytes witch length is 512 bits, the block size in SHA-1
        byte[] ipad = {0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 
                       0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                       0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                       0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                       0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                       0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                       0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                       0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36};

        //converts opad to String
        String strOpad = new String(opad);
        //converts ipad to String
        String strIpad = new String(ipad);

        // applies the HMAC function on the inputs provided (hmacKey and message),
        // uses the function stringXor to perform the exclusive or (XOR) operation
        // on the strings
		String code = new String();
		try {
			code = HashGenerator.generateHash(stringXor(hmacKey, strOpad)
					+ HashGenerator.generateHash((stringXor(hmacKey, strIpad))
							+ message));
		} catch (NoSuchAlgorithmException e) {
			logger.log(Level.SEVERE,"",e);
		} catch (UnsupportedEncodingException e) {
			logger.log(Level.SEVERE,"",e);
		}

		return code;
    }
   
}

