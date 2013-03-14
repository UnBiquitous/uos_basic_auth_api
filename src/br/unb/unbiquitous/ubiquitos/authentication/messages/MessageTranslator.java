package br.unb.unbiquitous.ubiquitos.authentication.messages;


public class MessageTranslator {

	
	/** 
	 * Generates a string representing the input message. The string 
	 * is formed by the concatenation of the fields of the message, 
	 * separated by the separator ":". 
	 * 
	 * Not all fields of the message is copied to the string, only those 
	 * that serve as input to the second step of the protocol. The order 
	 * of fields in the string is as follows:
	 * 
	 * hashId : idEc : ra1Enc : ra2Enc : hmac  
	 * 
	 * @param firstMessage - the message which fields will form the string.
	 * @return strFirstMessage - the string described above.
	 * */
	
	public String generateSecondStepInput (FirstMessage firstMessage){
		
		String strFirstMessage =
			generateField(firstMessage.getHashId()) + ":" +
			generateField(firstMessage.getIdEnc())  + ":" +
			generateField(firstMessage.getRa1Enc()) + ":" +
			generateField(firstMessage.getRa2Enc()) + ":" +
			generateField(firstMessage.getHmacM1());
			
		return strFirstMessage;
	}

	
	/** 
	 * Generates a string representing the input message. The string 
	 * is formed by the concatenation of the fields of the message, 
	 * separated by the separator ":". 
	 * 
	 * Not all fields of the message is copied to the string, only those 
	 * that serve as input to the third step of the protocol. The order 
	 * of fields in the string is as follows:
	 * 
	 * hmac : idEnc : ra1IncEnc : ra2IncEnc : rb1Enc : rb2Enc  
	 * 
	 * @param secondMessage - the message which fields will form the string.
	 * @return strSecondMessage - the string described above.
	 * */
	
	public String generateThirdStepInput (SecondMessage secondMessage){
		
		String strSecondMessage = 
			generateField(secondMessage.getHmac()) + ":" +
			generateField(secondMessage.getIdEnc()) + ":" +
			generateField(secondMessage.getRa1IncEnc()) + ":" +
			generateField(secondMessage.getRa2IncEnc()) + ":" +
			generateField(secondMessage.getRb1Enc()) + ":" +
			generateField(secondMessage.getRb2Enc());
		
		return strSecondMessage;
	}
	

	/** 
	 * Generates a string representing the input message. The string 
	 * is formed by the concatenation of the fields of the message, 
	 * separated by the separator ":". 
	 * 
	 * Not all fields of the message is copied to the string, only those 
	 * that serve as input to the fourth step of the protocol. The order 
	 * of fields in the string is as follows:
	 * 
	 * sessionKeyEnc : hmac
	 * 
	 * @param thirdMessage - the message which fields will form the string.
	 * @return strThirdMessage - the string described above.
	 * */
	
	public String generateFourthStepInput (ThirdMessage thirdMessage){

		String strThirdMessage =
			generateField(thirdMessage.getSessionKeyEnc()) + ":" +
			generateField(thirdMessage.getHmac());
		
		return strThirdMessage;
	}
	
		
	/** 
	 * Generates a first message object from a string that represents this 
	 * message (constructed by method generateSecondStepInput). This string
	 * has fields hashId : idEc : ra1Enc : ra2Enc : hmac
	 * 
	 * @param strMessage - the string used to generate the object
	 * @return firstMessage - the message generated from String 
	 * */
	
	public FirstMessage generateFirstMessage (String strMessage){
		
		int nextSeparatorIndex = 0;
		int lastSeparatorIndex = 0;
		
		nextSeparatorIndex = strMessage.indexOf(":", lastSeparatorIndex);
		String hashId = strMessage.substring(0, nextSeparatorIndex);

		lastSeparatorIndex = nextSeparatorIndex;
		nextSeparatorIndex = strMessage.indexOf(":", lastSeparatorIndex+1);
		String idEnc = strMessage.substring(lastSeparatorIndex+1, nextSeparatorIndex);
		
		lastSeparatorIndex = nextSeparatorIndex;
		nextSeparatorIndex = strMessage.indexOf(":", lastSeparatorIndex+1);
		String ra1Enc = strMessage.substring(lastSeparatorIndex+1, nextSeparatorIndex);
		
		lastSeparatorIndex = nextSeparatorIndex;
		nextSeparatorIndex = strMessage.indexOf(":", lastSeparatorIndex+1);
		String ra2Enc = strMessage.substring(lastSeparatorIndex+1, nextSeparatorIndex);
		
		lastSeparatorIndex = nextSeparatorIndex;
		String hmac = strMessage.substring(lastSeparatorIndex+1, strMessage.length());
		
		FirstMessage firstMessage = new FirstMessage();
		firstMessage.setHashId(generateField(hashId));
		firstMessage.setIdEnc(generateField(idEnc));
		firstMessage.setRa1Enc(generateField(ra1Enc));
		firstMessage.setRa2Enc(generateField(ra2Enc));
		firstMessage.setHmacM1(generateField(hmac));
		
		return firstMessage;
		
	}
	
	
	/** 
	 * Generates a second message object from a string that represents this 
	 * message (constructed by method generateThirdStepInput). This string
	 * has fields hmac : idEnc : ra1IncEnc : ra2IncEnc : rb1Enc : rb2Enc 
	 * 
	 * @param strMessage - the string used to generate the object
	 * @return secondMessage - the message generated from String 
	 * */
	
	public SecondMessage generateSecondMessage (String strMessage){
		
		int nextSeparatorIndex = 0;
		int lastSeparatorIndex = 0;
		
		nextSeparatorIndex = strMessage.indexOf(":", lastSeparatorIndex);
		String hmac = strMessage.substring(0, nextSeparatorIndex);
		
		lastSeparatorIndex = nextSeparatorIndex;
		nextSeparatorIndex = strMessage.indexOf(":", lastSeparatorIndex+1);
		String idEnc = strMessage.substring(lastSeparatorIndex+1, nextSeparatorIndex);
		
		lastSeparatorIndex = nextSeparatorIndex;
		nextSeparatorIndex = strMessage.indexOf(":", lastSeparatorIndex+1);
		String ra1IncEnc = strMessage.substring(lastSeparatorIndex+1, nextSeparatorIndex);
		
		lastSeparatorIndex = nextSeparatorIndex;
		nextSeparatorIndex = strMessage.indexOf(":", lastSeparatorIndex+1);
		String ra2IncEnc = strMessage.substring(lastSeparatorIndex+1, nextSeparatorIndex);
		
		lastSeparatorIndex = nextSeparatorIndex;
		nextSeparatorIndex = strMessage.indexOf(":", lastSeparatorIndex+1);
		String rb1Enc = strMessage.substring(lastSeparatorIndex+1, nextSeparatorIndex);
		
		lastSeparatorIndex = nextSeparatorIndex;
		String rb2Enc = strMessage.substring(lastSeparatorIndex+1, strMessage.length());
		
		SecondMessage secondMessage = new SecondMessage();
		secondMessage.setHmac(generateField(hmac));
		secondMessage.setIdEnc(generateField(idEnc));
		secondMessage.setRa1IncEnc(generateField(ra1IncEnc));
		secondMessage.setRa2IncEnc(generateField(ra2IncEnc));
		secondMessage.setRb1Enc(generateField(rb1Enc));
		secondMessage.setRb2Enc(generateField(rb2Enc));
		
		return secondMessage;
	}

	
	/** 
	 * Generates a fourth message object from a string that represents this 
	 * message (constructed by method generateFourthStepInput). This string
	 * has fields sessionKeyEnc : hmac 
	 * 
	 * @param strMessage - the string used to generate the object
	 * @return thirdMessage - the message generated from String 
	 * */
	
	public ThirdMessage generateThirdMessage (String strMessage){

		int nextSeparatorIndex = 0;
		int lastSeparatorIndex = 0;
		
		nextSeparatorIndex = strMessage.indexOf(":", lastSeparatorIndex);
		String sessionKeyEnc = strMessage.substring(0, nextSeparatorIndex);

		lastSeparatorIndex = nextSeparatorIndex;
		String hmac = strMessage.substring(lastSeparatorIndex+1, strMessage.length());
		
		ThirdMessage thirdMessage = new ThirdMessage();
		thirdMessage.setSessionKeyEnc(generateField(sessionKeyEnc));
		thirdMessage.setHmac(generateField(hmac));
		
		return thirdMessage;
	}
	
	/** 
	 * 
	 * */
	public String generateField (String str){
		
		if (str == null){
			return "null";
		} else { 
		
			if (str.equals("null")){
				return null;
			} else {
				return str;
			}
		}
	}

}
