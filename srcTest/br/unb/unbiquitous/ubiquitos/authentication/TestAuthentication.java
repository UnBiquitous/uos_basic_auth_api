package br.unb.unbiquitous.ubiquitos.authentication;
//import gnu.crypto.mac.HMac;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import junit.framework.TestCase;
import br.unb.unbiquitous.ubiquitos.authentication.exception.DuplicateIdException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.IdNotFoundException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.IdNotInformedException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.InvalidHMACException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.InvalidHashIdException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.KeyNotInformedException;
import br.unb.unbiquitous.ubiquitos.authentication.messages.FirstMessage;
import br.unb.unbiquitous.ubiquitos.authentication.messages.SecondMessage;
import br.unb.unbiquitous.ubiquitos.authentication.messages.ThirdMessage;


/** 
 * Class responsible to test several possible situations, for example, successful authentication,
 * authentication error when an incorrect key or an inexistent id is informed.  
 * */
public class TestAuthentication extends TestCase {

	AuthenticationDao authenticationDao;
	SessionKeyDao sessionKeyDao;
	private AuthenticationHandler authentication;
	
	public TestAuthentication() {

		String TABLE_NAME = "authenticationData";
		String ID_COLUMN_NAME = "id";
    	String KEY_COLUMN_NAME = "key";
    	String HASHID_COLUMN_NAME = "hashId";
		
		try {
			AuthenticationDaoHSQLDB authenticationDaoHSQLDB = new AuthenticationDaoHSQLDB(); 
			authenticationDao = authenticationDaoHSQLDB;
			SessionKeyDaoHSQLDB sessionKeyDaoHSQLDB = new SessionKeyDaoHSQLDB(); 
			sessionKeyDao = sessionKeyDaoHSQLDB;
			
			authentication = new AuthenticationHandler(authenticationDao, sessionKeyDao);
			
			Connection con = authenticationDaoHSQLDB.connect();
			
			// clean database
			String sql = "";
			PreparedStatement stm = con.prepareStatement(sql);
			sql = "delete from " + TABLE_NAME;
			stm = con.prepareStatement(sql);
			stm.executeUpdate();
			stm.close();

			// inserts data to database
			PreparedStatement pstmt;
			
			pstmt = con.prepareStatement("insert into  " + TABLE_NAME + "(" + ID_COLUMN_NAME + ", " + KEY_COLUMN_NAME + ", " + HASHID_COLUMN_NAME + ") values ('LocalDummyDevice', '5f8d93682477592c1479ee7803ac44e1', 'e4902e2bd52e1515daba7172dbc0f75c622460b7');");
			pstmt.executeUpdate();
			
			//close connection
			con.close();
		} catch (SQLException e) {
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}
	}
	

	/** 
	 * Tests successful authentication when correct id and key are informed.
	 * Expected result is that all steps of authentication are correct executed
	 * and the last step returns true.
	 * */
	public void testeSucessoAutenticacao() throws Exception {  

		System.out.println("########## testeSucessoAutenticacao ##########");
		
		Cipher cifra = new Cipher("5f8d93682477592c1479ee7803ac44e1");
		
		FirstMessage m1 = authentication.runFirstStep("LocalDummyDevice", "5f8d93682477592c1479ee7803ac44e1");
		assertEquals("hashId gravado incorretamente em m1 ", "e4902e2bd52e1515daba7172dbc0f75c622460b7", m1.getHashId());
		
		String m1EncRa1 = m1.getRa1Enc();
		assertEquals("encriptacao incorreta de ra1 em m1 ", cifra.encrypt(m1.getRa1()), m1EncRa1);

		String m2EncRa2 = m1.getRa2Enc();
		assertEquals("encriptacao correta de ra2 em m1 ", cifra.encrypt(m1.getRa2()), m2EncRa2);

		//check hmac(m1)
		String hmacEsperado = HMacUtils.generateHMac(m1.getRa2(), m1.getHashId() + m1.getIdEnc() + m1.getRa1Enc() + m1.getRa2Enc());
		assertEquals(hmacEsperado , m1.getHmacM1());

		// check second message
		// m1 = "H1:" + hashId + "*" + idEncriptado + "@" + ra1Encriptado + "#" + ra2Encriptado;
		// m2 = "H2:" + idEncriptadoM2 + "*" + ra1IncEncriptadoM2 + "@" + ra2IncEncriptadoM2 + "#" + rb1EncriptadoM2 + "%" + rb2EncriptadoM2;
		// run second step
		
		SecondMessage m2 = authentication.runSecondStep(m1.getHashId(), m1.getIdEnc(), m1.getRa1Enc(), m1.getRa2Enc(), m1.getHmacM1());
		if (m2 == null){
			System.out.println("M2 NULL");
		} else{
			System.out.println("M2 != NULL");
		}
		
		
		// check encoded id
		assertEquals(m2.getIdEnc(), m1.getIdEnc());
		// check Eka(ra+1)
		String ra1IncEncM1 = cifra.encrypt(authentication.increment(m1.getRa1()));
		assertEquals(m2.getRa1IncEnc(), ra1IncEncM1);
		//check Eka(ra'+1)
		String ra2IncEncriptadoM1 = cifra.encrypt(authentication.increment(m1.getRa2()));
		assertEquals(m2.getRa2IncEnc(), ra2IncEncriptadoM1);
		
		// check third message
		ThirdMessage m3 = authentication.runThirdStep("5f8d93682477592c1479ee7803ac44e1", m1.getRa1(), m1.getRa2(), "LocalDummyDevice", 
				m2.getHmac(), m2.getIdEnc(), m2.getRa1IncEnc(), m2.getRa2IncEnc(), m2.getRb1Enc(), m2.getRb2Enc());
		
		// gets rb from m2
		String rb = cifra.decrypt((m2.getRb1Enc()));
		// calculation of rb +1
		String rbInc = authentication.increment(rb);
		Cipher c3 = new Cipher(rb); 
		// check session key (rb+1)
		assertEquals(m3.getSessionKeyEnc(), c3.encrypt(rbInc));

		// last step
		assertTrue("erro na autenticação com sucesso", authentication.runFourthStep(m3.getSessionKeyEnc(), m2.getRb1(), m3.getHmac(), m3.getId()));
		
	}  

	
	/** 
	 * Tests authentication error when the key is not informed. The expected 
	 * result is KeyNotInformedException in first step.
	 * */
	public void testeChaveNaoInformada() throws Exception{
		
		System.out.println();
		System.out.println("########## testeChaveNaoInformada ##########");
		
		try{
			authentication.runFirstStep("0004", "");
		
		} catch (KeyNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
		} 
	}
	
	
	/** 
	 * Tests authentication error when the id is not informed. The expected 
	 * result is IdNotInformedException in first step.
	 * */
	public void testeIdNaoInformado() throws Exception{
		
		System.out.println();
		System.out.println("########## testeIdNaoInformado ##########");
		try{
			authentication.runFirstStep("", "5f8d93682477592c1479ee7803ac44e1");
		  	
		} catch (IdNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
		} 
	}
	

	/** 
	 * Tests authentication error when the id and the key is not informed. 
	 * The expected result is IdNotInformedException in first step.
	 * */
	public void testeIdeChaveNaoInformados() throws IdNotInformedException, BadPaddingException, InvalidKeyException,
	 NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, KeyNotInformedException{
		
		System.out.println();
		System.out.println("########## testeIdeChaveNaoInformado ##########");
		
		try{
			authentication.runFirstStep("", "");
		
		//expected exception	
		} catch (IdNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
		} 
		//unexpected exceptions
		 catch (BadPaddingException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (InvalidKeyException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (NoSuchPaddingException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (NoSuchAlgorithmException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (IllegalBlockSizeException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (KeyNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (Exception e){
			
		}
	}
	
	
	/** 
	 * Tests authentication error when an incorrect key is informed. 
	 * The expected result is BadPaddingException in second step.
	 * */
	public void testeChaveIncorreta() throws BadPaddingException{

		System.out.println();
		System.out.println("########## testeChaveIncorreta ##########");
		try{
			FirstMessage m1 = authentication.runFirstStep("LocalDummyDevice", "5d8d93682477592c1479ee7803ac44e1");
			authentication.runSecondStep(m1.getHashId(), m1.getIdEnc(), m1.getRa1Enc(), m1.getRa2Enc(), m1.getHmacM1());
		// expected exception
		} catch (BadPaddingException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
		} 
		//unexpected exceptions
		  catch (NoSuchPaddingException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (NoSuchAlgorithmException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (IllegalBlockSizeException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (SQLException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (InvalidHMACException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (IdNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (KeyNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (InvalidKeyException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (InvalidHashIdException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (IdNotFoundException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (DuplicateIdException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (Exception e){
			
		}
	}
	
	
	/** 
	 * Tests authentication error when is informed an id that is not in database. The expected 
	 * result is IdNotFoundException in second step.
	 * */
	public void testeIdInexistente(){
		
		System.out.println();
		System.out.println("########## testeIdInexistente ##########");
		try{
			FirstMessage m1 = authentication.runFirstStep("LocalDummyDevice1", "5f8d93682477592c1479ee7803ac44e2");
			authentication.runSecondStep(m1.getHashId(), m1.getIdEnc(), m1.getRa1Enc(), m1.getRa2Enc(), m1.getHmacM1());

		// expected exception	
		} catch (IdNotFoundException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
		} //unexpected exceptions
		 catch (IdNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (KeyNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (InvalidHashIdException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (InvalidHMACException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}  catch (DuplicateIdException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (NoSuchPaddingException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (NoSuchAlgorithmException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (BadPaddingException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (InvalidKeyException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (IllegalBlockSizeException e) {
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (SQLException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (Exception e){
			
		}
	} 
	

	/** 
	 * Tests authentication error when the original message generated from one step of the 
	 * authentication is changed. There are lot of errors that can occur when a message is 
	 * changed by an attacker, depending on where the modification was done and what was modified.
	 * Some possible errors are: InvalidHashIdException, IdNotFoundException and InvalidHmacException.   
	 * */
	public void testeAdulteracaoM1(){
		
		System.out.println();
		System.out.println("########## testeAdulteracaoM1 ##########");
		try{
			new Cipher("5f8d93682477592c1479ee7803ac44e1");
			FirstMessage m1 = authentication.runFirstStep("LocalDummyDevice", "5f8d93682477592c1479ee7803ac44e1");
			
			// the part of the message corresponding to HMACra'(M1) was modified to "123"
			authentication.runSecondStep("e4902e2bd52e1515daba7172dbc0f75c622460b7", 
					m1.getIdEnc() , m1.getRa1Enc(), m1.getRa2Enc(), "123");
		
		//expected exception	
		} catch (InvalidHMACException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
		}
		//unexpected exceptions
		  catch (IdNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (IllegalBlockSizeException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.SEVERE, e.toString(), e);
			fail();
		} catch (NoSuchPaddingException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.SEVERE, e.toString(), e);
			fail();
		} catch (NoSuchAlgorithmException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.SEVERE, e.toString(), e);
			fail();
		} catch (InvalidKeyException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.SEVERE, e.toString(), e);
			fail();
		} catch (KeyNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (InvalidHashIdException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}  catch (IdNotFoundException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (DuplicateIdException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (BadPaddingException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.SEVERE, e.toString(), e);
			fail();
		} catch (SQLException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.SEVERE, e.toString(), e);
			fail();
		} catch (Exception e){
			
		}
	}
	
}
