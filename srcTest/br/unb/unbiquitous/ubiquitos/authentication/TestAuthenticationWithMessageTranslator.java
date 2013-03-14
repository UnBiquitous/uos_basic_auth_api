package br.unb.unbiquitous.ubiquitos.authentication;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

import junit.framework.TestCase;
import br.unb.unbiquitous.ubiquitos.authentication.messages.FirstMessage;
import br.unb.unbiquitous.ubiquitos.authentication.messages.MessageTranslator;
import br.unb.unbiquitous.ubiquitos.authentication.messages.SecondMessage;
import br.unb.unbiquitous.ubiquitos.authentication.messages.ThirdMessage;


/** 
 * Class responsible to test several possible situations, for example, successful authentication,
 * authentication error when an incorrect key or an inexistent id is informed.  
 * */
public class TestAuthenticationWithMessageTranslator extends TestCase {

	AuthenticationDao authenticationDao;
	SessionKeyDao sessionKeyDao;
	private AuthenticationHandler authentication;
	
	public TestAuthenticationWithMessageTranslator() {

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
			Logger.getLogger(TestAuthenticationWithMessageTranslator.class.getName()).log(Level.INFO, e.toString(), e);
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
		
		MessageTranslator mt = new MessageTranslator();
		
		new Cipher("5f8d93682477592c1479ee7803ac44e1");
		
		FirstMessage m1 = authentication.runFirstStep("LocalDummyDevice", "5f8d93682477592c1479ee7803ac44e1");
		String strM1 = mt.generateSecondStepInput(m1);
		SecondMessage mtM2 = authentication.runSecondStep(strM1);
		
		SecondMessage m2 = authentication.runSecondStep(m1.getHashId(), m1.getIdEnc(), m1.getRa1Enc(), m1.getRa2Enc(), m1.getHmacM1());

		assertEquals (m2.getId(), mtM2.getId());
		assertEquals (m2.getIdEnc(), mtM2.getIdEnc());
		assertEquals (m2.getRa1Inc(), mtM2.getRa1Inc());
		assertEquals (m2.getRa2Inc(), mtM2.getRa2Inc());
		
		ThirdMessage mtM3 = authentication.runThirdStep ("5f8d93682477592c1479ee7803ac44e1", m1.getRa1(), 
				m1.getRa2(), "LocalDummyDevice", mt.generateThirdStepInput(m2));
		
		ThirdMessage m3 = authentication.runThirdStep("5f8d93682477592c1479ee7803ac44e1", m1.getRa1(), m1.getRa2(), "LocalDummyDevice", 
				m2.getHmac(), m2.getIdEnc(), m2.getRa1IncEnc(), m2.getRa2IncEnc(), m2.getRb1Enc(), m2.getRb2Enc());
		
		assertEquals (m3.getId(), mtM3.getId());
		assertEquals (m3.getSessionKey(), mtM3.getSessionKey());
		assertEquals (m3.getSessionKeyEnc(), mtM3.getSessionKeyEnc());
		
		// last step

		System.out.println("m2.getId(): " + m2.getId());
		assertTrue("erro na autenticação com sucesso", authentication.runFourthStep(m2.getRb1(), m3.getId(), mt.generateFourthStepInput(m3)));
		
		assertTrue("erro na autenticação com sucesso", authentication.runFourthStep(m3.getSessionKeyEnc(), m2.getRb1(), m3.getHmac(), m3.getId()));
		
	}  
	
}
