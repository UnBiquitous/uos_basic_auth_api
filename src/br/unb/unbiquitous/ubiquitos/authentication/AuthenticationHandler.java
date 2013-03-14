package br.unb.unbiquitous.ubiquitos.authentication;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

import br.unb.unbiquitous.ubiquitos.authentication.exception.DuplicateIdException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.IdNotFoundException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.IdNotInformedException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.InvalidHMACException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.InvalidHashIdException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.InvalidSecondMessageException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.KeyNotInformedException;
import br.unb.unbiquitous.ubiquitos.authentication.messages.FirstMessage;
import br.unb.unbiquitous.ubiquitos.authentication.messages.MessageTranslator;
import br.unb.unbiquitous.ubiquitos.authentication.messages.SecondMessage;
import br.unb.unbiquitous.ubiquitos.authentication.messages.ThirdMessage;

/** 
 * Class responsible to execute the four steps os the authentication. The first and the third steps 
 * are executed by the device. The second and the fourth steps are executed by the middleware.  
 * */
public class AuthenticationHandler {
	private static final Logger logger = Logger.getLogger(AuthenticationHandler.class.getName());
	
	// attributes used to define what DAOs will be used in an instance of Authentication
	private AuthenticationDao authenticationDao;
	private SessionKeyDao sessionKeyDao;
	
	// default constructor
	public AuthenticationHandler() {}
	
	// constructor that allows specify what DAOs will be used
	public AuthenticationHandler(AuthenticationDao authenticationDao, SessionKeyDao sessionKeyDao) {
		this.authenticationDao = authenticationDao;
		this.sessionKeyDao = sessionKeyDao; 
	}
	
	public SessionKeyDao getSessionKeyDao() {
		return sessionKeyDao;
	}

	/** 
	 * Receives the device's id and the device's key and generates the firstMessage (hash(id), Eka(id, ra, ra'))
	 * @param id - the device's identificator
	 * @param key - the device's key
	 * @return firstMessage
	 * */
	public FirstMessage runFirstStep(String id, String key) throws Exception {	
	
		FirstMessage firstMessage = new FirstMessage();
		String m1 = null;
		
		if (authenticationDao != null){
			
			if (id == null || id.isEmpty()){
				throw new IdNotInformedException();
			} 
			else {
				if (key == null || key.isEmpty()){
					throw new KeyNotInformedException();
				} 
				else{
					// generates hash(id)
					String hashId = null;
					try{
						hashId = HashGenerator.generateHash(id);
						firstMessage.setHashId(hashId);
					}
					catch (NoSuchAlgorithmException ex){
						logger.log(Level.SEVERE,ex.toString());
					}
					catch (UnsupportedEncodingException ex){
						logger.log(Level.SEVERE,ex.toString());
					}
			        
					//generates the first random, ra
			        Cipher c1 = new Cipher();
			        String ra1 = c1.toHex(c1.getRaw());
			        firstMessage.setRa1(ra1);
			        
			        //generates the second random, ra'
			        Cipher c2 = new Cipher();
			        String ra2 = c2.toHex(c2.getRaw());
			        firstMessage.setRa2(ra2);
			        
			        // generates a new Cifra, to encode ra, ra1 and id
			        Cipher cifra= new Cipher(key);
			        try{
			        	// encode the randons and the id
			        	String ra1Encriptado = cifra.encrypt(ra1);
			        	String ra2Encriptado = cifra.encrypt(ra2);
			        	String idEncriptado = cifra.encrypt(id);
			        	
			        	//stores encoded randons and id in firstMessage 
			        	firstMessage.setRa1Enc(ra1Encriptado);
			        	firstMessage.setRa2Enc(ra2Encriptado);
			        	firstMessage.setIdEnc(idEncriptado);
			        	
			        	// concatenate data, to generate the first messagem
			        	m1 = hashId + idEncriptado + ra1Encriptado + ra2Encriptado;
			        	String hmacM1 = HMacUtils.generateHMac(ra2, m1);
			        	
			        	// stores HMAC(ra',m1) in the return object 
			        	firstMessage.setHmacM1(hmacM1);
			        	
			        } catch (Exception ex) {
			        	logger.log(Level.SEVERE,ex.toString());
			        	throw ex;
			        }
				}
			}
			
			// returns the object with message data
	        return firstMessage;
		} else{
			return null;
		}
	}
	
	/**
	 * Receives encoded fields of the first message and check if this message is correct. To check it, the method 
	 * decodes this fields using the device's key (Ka) and compares them with the real values. If they are correct
	 * and HMAC(ra', m1) is also correct generates the second message, Eka(Id,ra,ra',rb,rb') HMAC(rb', m2), else, 
	 * throws an exception. 
	 *
	 * @param hashId - hash(id)
	 * @param idEncriptadoM1 - encoded id, Eka(id)
	 * @param ra1EncriptadoM1 - encoded ra, Eka(ra)
	 * @param ra2EncriptadoM1 - encoded ra', Eka(ra')
	 * @param hmacM1 - HMAC(ra', m1) first message authentication code
	 * 
	 * @return secondMessage
	 * */
	public SecondMessage runSecondStep(String hashId, String idEncriptadoM1, String ra1EncriptadoM1, String ra2EncriptadoM1, String hmacM1) throws Exception {		

		String m2 = null;
		SecondMessage secondMessage = new SecondMessage();
		
            // check the first message
            try {
            	logger.info("Search for hashID: " + hashId);
            	AuthenticationData h = authenticationDao.findByHashId(hashId);
            	            	
        		if (h != null){
        			String id = h.getId();
                	String ka = h.getKey();
                	
                    Cipher cifra = new Cipher(ka);

	            	String idDecriptadoM1 = cifra.decrypt(idEncriptadoM1);                    
	            	
	            	// checks if the id encoded in the first message is the same for which the hash was generated
	            	if (!id.equals(idDecriptadoM1)){
	            		throw new InvalidHashIdException();
	                } 
	            	else{
	            		//decodes ra and ra'
		            	String ra1DecriptadoM1 = cifra.decrypt(ra1EncriptadoM1);
		            	
		            	String ra2DecriptadoM1 = cifra.decrypt(ra2EncriptadoM1);
		            	
		            	//checks HMAC(ra', m1)
		            	String m1 = hashId + idEncriptadoM1 + ra1EncriptadoM1 + ra2EncriptadoM1;
		            	String hmacRa2m1 = HMacUtils.generateHMac(ra2DecriptadoM1, m1);
		            	
		            	if (!hmacRa2m1.equals(hmacM1)){
		            		throw new InvalidHMACException();
		            	}
		            	else{
		            		secondMessage.setId(id);
		            		// makes the second message
			        		Cipher c = new Cipher();
			        		
			        		// generates middleware's random numbers, rb and rb', and stores in the secondMessage object
			        		String rb1 = c.toHex(c.getRaw());
			        		secondMessage.setRb1(rb1);
	
			        		String rb2 = c.toHex(c.getRaw());
			        		secondMessage.setRb2(rb2);

			                // encodes ra and ra'
			        		String idEncriptadoM2 = cifra.encrypt((idDecriptadoM1));
			        		String ra1IncEncriptadoM2 = cifra.encrypt(increment(ra1DecriptadoM1));
			        		String ra2IncEncriptadoM2 = cifra.encrypt(increment(ra2DecriptadoM1));
			        		
			                // stores ra and ra' in the output object
			                secondMessage.setRa1Inc(increment(ra1DecriptadoM1));
			                secondMessage.setRa2Inc(increment(ra2DecriptadoM1));
			                
			                // encodes rb and rb'
			                String rb1EncriptadoM2 = cifra.encrypt(rb1);
			                String rb2EncriptadoM2 = cifra.encrypt(rb2);

			                // creates the second message
			                m2 = idEncriptadoM2 + ra1IncEncriptadoM2 + ra2IncEncriptadoM2 + rb1EncriptadoM2 + rb2EncriptadoM2;
			                
			                // stores parts of the second message in the output object
			                secondMessage.setIdEnc(idEncriptadoM2);
			                secondMessage.setRa1IncEnc(ra1IncEncriptadoM2);
			                secondMessage.setRa2IncEnc(ra2IncEncriptadoM2);
			                secondMessage.setRb1Enc(rb1EncriptadoM2);
			                secondMessage.setRb2Enc(rb2EncriptadoM2);
			                
			                // generates HMAC(rb',m2)
			                String hmacM2 = HMacUtils.generateHMac(rb2, m2);
			                secondMessage.setHmac(hmacM2);
		            	}
	                }
        		} else{
                	throw new IdNotFoundException();
                } 
            } catch (SQLException ex) {
            	logger.log(Level.SEVERE,ex.toString());
                throw ex;
            } catch (DuplicateIdException ex) {
            	logger.log(Level.SEVERE,ex.toString());
                throw ex;
            } catch (Exception ex) {
            	logger.log(Level.SEVERE,ex.toString());
                throw ex;
            }   
                
            // stores the second message in the output object
    		return secondMessage;
        }
        
	
	/** 
	 * Receives encoded fields of the second message and check if this message is correct. To check it, the method 
	 * decodes this fields using the device's key (Ka) and compares them with the real values. If they are correct
	 * and HMAC(rb', m2) is also correct generates the third message, Erb(rb+1), and send this message and 
	 * HMAC(rb, m3), else, throws an exception. 
	 * 
	 * @param ka - device's key
	 * @param ra1 - random number generated in the first step (ra)
	 * @param ra2 - random number generated in the first step (ra')
	 * @param id - device's id
	 * @param m2 - second message, generated in the second step
	 * @param hmacM2 - HMAC(rb', m2)
	 * 
	 * @return thirdMessage
	 * */
	public ThirdMessage runThirdStep(String ka, String ra1, String ra2, String id, String hmacM2, String idEncriptadoM2, 
			String ra1IncEncriptadoM2, String ra2IncEncriptadoM2, String rb1EncriptadoM2, String rb2EncriptadoM2) 
	throws Exception {
		
		ThirdMessage thirdMessage = new ThirdMessage();
		Cipher cifra = null;
		
        cifra = new Cipher(ka);

        try {
        	
            // decodes data received from m2
        	String idDecriptadoM2 = cifra.decrypt(idEncriptadoM2);
            String ra1IncDecriptadoM2 = cifra.decrypt(ra1IncEncriptadoM2);
            String ra2IncDecriptadoM2 = cifra.decrypt(ra2IncEncriptadoM2);
            
            // validades id, ra and ra'
            if (!ra1IncDecriptadoM2.equals(increment(ra1)) || !(ra2IncDecriptadoM2.equals(increment(ra2))) || !idDecriptadoM2.equals(id)){
            	throw new InvalidSecondMessageException();
            }
            else {
            	// decodes rb and rb'
            	String rb1DecriptadoM2 = cifra.decrypt((rb1EncriptadoM2));
                String rb2DecriptadoM2 = cifra.decrypt(rb2EncriptadoM2);

                // check HMAC(m2)
                String m2 = idEncriptadoM2 + ra1IncEncriptadoM2 + ra2IncEncriptadoM2 + rb1EncriptadoM2 + rb2EncriptadoM2;
                String hmacRb2m2 = HMacUtils.generateHMac(rb2DecriptadoM2, m2);
                if (!hmacRb2m2.equals(hmacM2)){
                	throw new InvalidHMACException();
                }
                else{
                	
                	// creates the key session (rb+1)
                    String chaveSessao = increment(rb1DecriptadoM2);
                    thirdMessage.setSessionKey(chaveSessao);
                    
 	                // encodes the key session
                    Cipher c = new Cipher(rb1DecriptadoM2);
 	                String chaveSessaoEncriptada = c.encrypt(chaveSessao);
 	                
 	                // stores encoded sesstion key
 	                thirdMessage.setSessionKeyEnc(chaveSessaoEncriptada);
 	                
 	                // generates de HMAC(m3)
 	               String hmacChaveSessaom3 = HMacUtils.generateHMac(chaveSessao, chaveSessaoEncriptada);
 	               thirdMessage.setHmac(hmacChaveSessaom3);
 	               
 	               //stores id in output object
 	              thirdMessage.setId(id);
                }
            }
                
        } catch (Exception ex) {
        	logger.log(Level.SEVERE,ex.toString());
          	throw ex; 
        } 
		        
		return thirdMessage;
	}
	
	/** 
	 * Receives a message with encoded key session and decodes this message with rb. Then increments
	 * rb1, to generate key session and compares this session and the decoded hash(id). If they are
	 * equals the method returns true, else, the returns false.
	 * 
	 * @param m3 - third message
	 * @param rb1 - middleware random (rb)
	 * @param hmacM3 - hmac(rb', m3)
	 * @return retorno - true, if the authentication was successful, or false, if it wasn't
	 * */
	public boolean runFourthStep (String chaveSessaoEncriptadaM3, String rb1, String hmacM3, String id) throws Exception{

		boolean retorno = false;
		
		try{
			// generates a new cipher with the key rb1 (the first random generated by the middleware)
			Cipher cifra = new Cipher(rb1);
			String rb1IncDecriptadoM3 = cifra.decrypt(chaveSessaoEncriptadaM3);				
			
			// checks (rb+1)
			if (rb1IncDecriptadoM3.equals(increment(rb1))){
				String hmacChaveSessaoM3 = HMacUtils.generateHMac(increment(rb1), chaveSessaoEncriptadaM3);
				//checks hmac. If it is ok, the authentication is successful
				if (hmacM3.equals(hmacChaveSessaoM3)){
					sessionKeyDao.insert(id, increment(rb1));
					retorno = true;
				}
			}
		} catch (Exception ex) {
			logger.log(Level.SEVERE,ex.toString());
            throw ex;
        } 
		
		return retorno;
	}
    
	/** 
	 * Gets a message (String) and returns another message, generated by replace the last character
	 * of the input message to the next character in the String "0123456789abcdef0". For example, if
	 * the input message is "ab32c6" the output message is "ab32c7"; if the input message is "ae432690f"
	 * the output message is "ae4326900".
	 *   
	 * @param mensagem - input message
	 * @param mensagem - output message (input message incremented)
	 * */
    public String increment (String mensagem){
    	
    	String ultima = mensagem.substring(mensagem.length() - 1);
        String digito = "0123456789abcdef0";
        int dig = digito.indexOf(ultima) + 1;
        ultima = digito.substring(dig, dig + 1);
        mensagem = mensagem.substring(0, mensagem.length() - 1) + ultima;
    	
    	return mensagem;
    }
    
    public SecondMessage runSecondStep(String strFirstMessage) throws Exception {
    	
    	MessageTranslator mt = new MessageTranslator();
    	
    	FirstMessage m1 = mt.generateFirstMessage(strFirstMessage);
    	
    	return runSecondStep (m1.getHashId(), m1.getIdEnc(), 
    			m1.getRa1Enc(), m1.getRa2Enc(), m1.getHmacM1());
    }
    
    
    public ThirdMessage runThirdStep(String ka, String ra1, String ra2, String id, 
    		String strSecondMessage) throws Exception {
    	
    	MessageTranslator mt = new MessageTranslator();
    	
    	SecondMessage m2 = mt.generateSecondMessage(strSecondMessage);
    	
    	return runThirdStep(ka, ra1, ra2, id, m2.getHmac(), m2.getIdEnc(), 
    			m2.getRa1IncEnc(), m2.getRa2IncEnc(), m2.getRb1Enc(), 
    			m2.getRb2Enc());
    }

    public boolean runFourthStep (String rb1, String id, String strThirdMessage) throws Exception{
    
    	MessageTranslator mt = new MessageTranslator();
    	
    	ThirdMessage m3 = mt.generateThirdMessage(strThirdMessage);
    	
    	return runFourthStep(m3.getSessionKeyEnc(), rb1, m3.getHmac(), id);
    }
    
}
