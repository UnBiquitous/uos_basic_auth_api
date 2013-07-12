package br.unb.unbiquitous.ubiquitos.uos.security.basic;

import java.sql.Time;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.unbiquitous.uos.core.AuthenticationHandler;
import org.unbiquitous.uos.core.UOSLogging;
import org.unbiquitous.uos.core.applicationManager.UOSMessageContext;
import org.unbiquitous.uos.core.messageEngine.MessageHandler;
import org.unbiquitous.uos.core.messageEngine.TranslationHandler;
import org.unbiquitous.uos.core.messageEngine.dataType.UpDevice;
import org.unbiquitous.uos.core.messageEngine.messages.ServiceCall;
import org.unbiquitous.uos.core.messageEngine.messages.ServiceResponse;

import br.unb.unbiquitous.ubiquitos.authentication.Cipher;
import br.unb.unbiquitous.ubiquitos.authentication.SessionData;
import br.unb.unbiquitous.ubiquitos.authentication.SessionKeyDao;
import br.unb.unbiquitous.ubiquitos.authentication.SessionKeyDaoHSQLDB;
import br.unb.unbiquitous.ubiquitos.authentication.exception.ExpiredSessionKeyException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.IdNotFoundException;
import br.unb.unbiquitous.ubiquitos.authentication.messages.FirstMessage;
import br.unb.unbiquitous.ubiquitos.authentication.messages.SecondMessage;
import br.unb.unbiquitous.ubiquitos.authentication.messages.ThirdMessage;

/**
 * 
 * Implementation of the basic method of authentication
 * 
 * @author Fabricio Nogueira Buzeto
 *
 */
public class BasicSecurityHandler implements AuthenticationHandler, TranslationHandler {

	private static final Logger logger = UOSLogging.getLogger();
	private static String SECURITY_TYPE = "BASIC";  
	SessionKeyDao sessionKeyDao = new SessionKeyDaoHSQLDB();;
	
	/**
	 * @see AuthenticationHandler#authenticate(ServiceCall, ServiceResponse, UOSMessageContext);
	 */
	@Override
	public void authenticate(ServiceCall serviceCall, ServiceResponse serviceResponse, UOSMessageContext messageContext) {
		
		AuthenticationDaoHSQLDB authenticationDao = new AuthenticationDaoHSQLDB();  
		
		br.unb.unbiquitous.ubiquitos.authentication.AuthenticationHandler authentication;
		authentication = new br.unb.unbiquitous.ubiquitos.authentication.AuthenticationHandler(authenticationDao, sessionKeyDao);
		
		sessionKeyDao = authentication.getSessionKeyDao();
		
		SecondMessage secondMessage = null;
		
		if (serviceCall.getParameters().containsKey("hashId")){
			
			logger.fine("Authenticate: middleware executes second step.");
			
			try{
				String hashId = (String) serviceCall.getParameters().get("hashId");
				String idEnc = (String) serviceCall.getParameters().get("idEnc");
				String ra1Enc = (String) serviceCall.getParameters().get("ra1Enc"); 
				String ra2Enc = (String) serviceCall.getParameters().get("ra2Enc");
				String hmacM1 = (String) serviceCall.getParameters().get("hmacM1");
				
				secondMessage = authentication.runSecondStep(hashId, idEnc, ra1Enc, ra2Enc, hmacM1);

				Map<String,Object> responseData = new HashMap<String,Object>();
				
				responseData.put("hmacM2", secondMessage.getHmac());
				responseData.put("idEnc", secondMessage.getIdEnc());
				responseData.put("ra1IncEnc", secondMessage.getRa1IncEnc());
				responseData.put("ra2IncEnc", secondMessage.getRa2IncEnc());
				responseData.put("rb1Enc", secondMessage.getRb1Enc());
				responseData.put("rb2Enc", secondMessage.getRb2Enc());
				
				serviceResponse.setResponseData(responseData);
	
			} catch (Exception e){
				Map<String,Object> responseData = new HashMap<String,Object>();
				responseData.put("error", e.toString());
				serviceResponse.setResponseData(responseData);
				logger.severe(e.toString());
			}
		}
		
		else {
			if (serviceCall.getParameters().containsKey("sessionKeyEnc")){
				
				logger.fine("Authenticate: middleware executes fourth step.");

				try{
						boolean result = authentication.runFourthStep (
								serviceCall.getParameterString("sessionKeyEnc"), 
								serviceCall.getParameterString("rb1"), 
								serviceCall.getParameterString("hmacM3"), 
								serviceCall.getParameterString("id"));

						Map<String,Object> responseData = new HashMap<String,Object>();

						if (result){
							responseData.put("result", "true");
							logger.fine("Authentication performed successfully. Service returned value \"true\"");
						} else{
							responseData.put("result", "false");
							logger.fine("Authentication failure. Service returned value \"false\"");
						}

						serviceResponse.setResponseData(responseData);
				} catch (Exception e){
					logger.severe(e.toString());
				}
			}
		}
	}

	/**
	 * @see AuthenticationHandler#authenticate(String, AdaptabilityEngine);
	 */
	@Override
	public void authenticate(UpDevice upDevice, MessageHandler messageHandler) {

		String deviceName = upDevice.getName();
		
		AuthenticationDaoHSQLDB authenticationDao = new AuthenticationDaoHSQLDB(); 
		String databaseName = "authenticationData" + deviceName;
		DeviceAuthenticationDaoHSQLDB deviceAutenticationDao = new DeviceAuthenticationDaoHSQLDB(databaseName); 
		
		br.unb.unbiquitous.ubiquitos.authentication.AuthenticationHandler authentication;
		authentication = new br.unb.unbiquitous.ubiquitos.authentication.AuthenticationHandler(authenticationDao, sessionKeyDao);
				
		try{
			logger.fine("Authenticate: device " +deviceName+ " starts authentication proccess.");
			
			String ka;
			
			try{
				logger.fine("Device retrieves key from database.");
				ka = deviceAutenticationDao.findById(deviceName).getKey();
			} catch (NullPointerException e){
				logger.severe("Id not found in database");
				throw new IdNotFoundException();
			}
			
			logger.fine("Device executes first step of authentication process.");
			FirstMessage firstMessage = authentication.runFirstStep(deviceName, ka);

			ServiceCall serviceCall = new ServiceCall();
			
			Map<String,Object> authenticationData = new HashMap<String,Object>();

			authenticationData.put("hashId", firstMessage.getHashId());
			authenticationData.put("idEnc", firstMessage.getIdEnc());
			authenticationData.put("ra1Enc", firstMessage.getRa1Enc());
			authenticationData.put("ra2Enc", firstMessage.getRa2Enc());
			authenticationData.put("hmacM1", firstMessage.getHmacM1());
			authenticationData.put("securityType", SECURITY_TYPE);
			
			serviceCall.setParameters(authenticationData);
			serviceCall.setServiceType(ServiceCall.ServiceType.DISCRETE);
			serviceCall.setService("authenticate");
			serviceCall.setDriver("uos.DeviceDriver");
			
			ServiceResponse serviceResponse = messageHandler.callService(upDevice, serviceCall);
			
			logger.fine("Device executes third step of authentication process.");
			ThirdMessage thirdMessage = authentication.runThirdStep(
					ka, 
					firstMessage.getRa1(), 
					firstMessage.getRa2(), 
					deviceName, 
					serviceResponse.getResponseString("hmacM2"),
					serviceResponse.getResponseString("idEnc"),
					serviceResponse.getResponseString("ra1IncEnc"),
					serviceResponse.getResponseString("ra2IncEnc"),
					serviceResponse.getResponseString("rb1Enc"),
					serviceResponse.getResponseString("rb2Enc"));
			
			authenticationData = new HashMap<String,Object>();
			authenticationData.put("sessionKeyEnc", thirdMessage.getSessionKeyEnc());
			authenticationData.put("hmacM3", thirdMessage.getHmac());
			authenticationData.put("id", thirdMessage.getId());
			authenticationData.put("securityType", SECURITY_TYPE);
			
			Cipher c = new Cipher(ka);
			authenticationData.put("rb1", c.decrypt(serviceResponse.getResponseString("rb1Enc")));
			
			serviceCall.setParameters(authenticationData);
			serviceResponse = new ServiceResponse();
			
			serviceResponse = messageHandler.callService(upDevice, serviceCall);

			logger.fine("Service Response after the fourth step: "+serviceResponse.getResponseData().values());
			
		} catch (Exception e){
			logger.log(Level.SEVERE,"",e);
		} 
	}
	
	/**
	 * @see AuthenticationHandler#getSecurityType();
	 * @see TranslationHandler#getSecurityType();
	 */
	@Override
	public String getSecurityType() {
		return SECURITY_TYPE;
	}
	
	/**
	 * @see TranslationHandler#decode(String, String)
	 */
	public String decode(String originalMessage, String deviceName){
		logger.fine("Uncapsulating request (decrypt) : "+originalMessage);
		logger.fine("Device name: "+deviceName);

		// creates new String to store result
		String processedMessage = null;
		
		try{
			//retrieves sessionKey
			SessionData sessionData = sessionKeyDao.findById(deviceName); 
			
			//retrieves expiration date
			Date expirationDate = sessionData.getExpirationDate();
			Time expirationTime = sessionData.getExpirationTime();					
			
			if (sessionKeyDao.isBeforeToday(expirationTime, expirationDate)){
	
//				//retrieves device's key
//				AuthenticationDao authenticationDao = new AuthenticationDaoHSQLDB();
//				AuthenticationData authenticationData = authenticationDao.findByHashId(HashGenerator.generateHash(deviceName));
//				//creates new cipher using device's key 
//								
//				Cipher cipher = new Cipher(authenticationData.getKey());
				
				Cipher cipher = new Cipher(sessionData.getSessionKey());
				
				//decrypts original message
				processedMessage = cipher.decrypt(originalMessage);
				
				logger.fine("into request: "+processedMessage);
				return processedMessage;
			} else{
				throw new ExpiredSessionKeyException();
			}
			
		} catch(Exception ex){ 
			logger.severe(ex.toString());
    	}
		return processedMessage;
	}
	
	/**
	 * @see TranslationHandler#encode(String, String)
	 */
	public String encode(String originalMessage, String deviceName){
		logger.fine("Encapsulating response : "+originalMessage+", device name:"+deviceName);

		// creates new String to store result
		String processedMessage = null;
		
		try{
			//retrieves sessionKey
			SessionData sessionData = sessionKeyDao.findById(deviceName); 

			//retrieves expiration date
			Date expirationDate = sessionData.getExpirationDate();
			Time expirationTime = sessionData.getExpirationTime();

			if (sessionKeyDao.isBeforeToday(expirationTime, expirationDate)){

//				//retrieves device's key
//				AuthenticationDao authenticationDao = new AuthenticationDaoHSQLDB();
//				AuthenticationData authenticationData = authenticationDao.findByHashId(HashGenerator.generateHash(deviceName));
//				
//				//creates new cipher using device's key 
//				Cipher cipher = new Cipher(authenticationData.getKey());
				
				Cipher cipher = new Cipher(sessionData.getSessionKey());
				
				//decrypts original message
				processedMessage = cipher.encrypt(originalMessage);
				logger.fine("into response (encrypt) : "+processedMessage);
				
				return processedMessage;
			} else{
				throw new ExpiredSessionKeyException();
			}
			
		} catch(Exception ex){ 
			logger.severe(ex.toString());
    	}
		
		return processedMessage;
	}
}
