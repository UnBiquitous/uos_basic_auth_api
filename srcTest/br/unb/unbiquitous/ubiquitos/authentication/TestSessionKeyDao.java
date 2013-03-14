package br.unb.unbiquitous.ubiquitos.authentication;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

import junit.framework.TestCase;
import br.unb.unbiquitous.ubiquitos.authentication.exception.DuplicateIdException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.ExpirationDateNotInformedException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.IdNotFoundException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.IdNotInformedException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.SessionKeyNotInformedException;

public class TestSessionKeyDao extends TestCase {

	SessionKeyDao sessionKeyDao;
	
	public TestSessionKeyDao() {

		String TABLE_NAME = "keySessionData";

		try {
			SessionKeyDaoHSQLDB sessionKeyDaoHSQLDB = new SessionKeyDaoHSQLDB(); 
			sessionKeyDao = sessionKeyDaoHSQLDB;
			
			Connection con = sessionKeyDaoHSQLDB.connect();
			
			// clean database
			String sql = "";
			PreparedStatement stm = con.prepareStatement(sql);
			sql = "delete from " + TABLE_NAME;
			stm = con.prepareStatement(sql);
			stm.executeUpdate();
			stm.close();

			new java.sql.Date((new java.util.Date()).getTime());
			
			// inserts data to database
			sessionKeyDao.insert("0004", "9512fa0b68a18832146849d8f6d2e9f2");
			sessionKeyDao.insert("0003", "5a68ca308ed8611b68640634514cdf00");
					
			//close connection
			con.close();
		} catch (SQLException e) {
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (SessionKeyNotInformedException e) {
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (IdNotInformedException e) {
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}
	}

	/* tests the update insertion in the different situations, for example tries to execute the method when 
	 * one of parameters was not informed, an executes correctly the update when parameters are correctly 
	 * informed and the id is in database*/
	public void testInsert() {
		try{
			// tries to insert an id that already exists in database. The expected result is IdAlreadyExistsException
			sessionKeyDao.insert("0004", "9512fa0b68a18832146849d8f6d2e9f2");
		}//unexpected exceptions  
		  catch (SessionKeyNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (IdNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}
		
		try{
			// tries to insert a new id in database. The expected result is successful insertion 
			sessionKeyDao.insert("0005", "83b6fff76aaf2abbe7b3688b80c1e6bd");
			assertEquals("83b6fff76aaf2abbe7b3688b80c1e6bd", sessionKeyDao.findById("0005").getSessionKey());	
		} catch (SessionKeyNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (IdNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (SQLException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (DuplicateIdException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}
		
		try{
			// tries to insert a new record, but not inform the id. The expected result is IdNotInformedException  
			sessionKeyDao.insert("", "83b6fff76aaf2abbe7b3688b80c1e6bd");
		} // expected exception
		  catch (IdNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
		} catch (SessionKeyNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}  

		try{
			// tries to insert a new record, but not inform the sessionKey. The expected result is SessionKeyNotInformedException 
			sessionKeyDao.insert("0006", "");
		} // expected exception
		  catch (SessionKeyNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
		} catch (IdNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}  
	}
	
	/* tests the update method in the different situations, for example tries to update a record that isn't 
	 * in database, tries to execute the method when one of parameters was not informed, an executes correctly 
	 * the update when parameter are correctly informed and the id is in database*/
	public void testUpdate() throws DuplicateIdException, SQLException{
		try{
			// try to update a record of database, but not inform new session key. The expected result is SessionKeyNotInformedException
			java.sql.Date dateToExpire = new java.sql.Date(new java.util.Date().getTime()); 
			java.sql.Time timeToExpire = new java.sql.Time(new java.util.Date().getTime() + 2*1000*60*60);
			
			assertNotNull(sessionKeyDao.findById("0004"));
			sessionKeyDao.update("0004", "", dateToExpire, timeToExpire);
		} catch (SessionKeyNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
		} catch (IdNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (IdNotFoundException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (ExpirationDateNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}

		try{
			// tries to update a record of database, but not inform the id. The expected result is IdKeyNotInformedException
			java.sql.Date dateToExpire = new java.sql.Date(new java.util.Date().getTime());
			java.sql.Time timeToExpire = new java.sql.Time(new java.util.Date().getTime() + 2*1000*60*60);
			
			
			sessionKeyDao.update("", "9512fa0b68a18832146849d8f6d2e9f2", dateToExpire, timeToExpire);
		} //expected exception
		  catch (IdNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
		} //unexpected exceptions
		  catch (SessionKeyNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (IdNotFoundException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (ExpirationDateNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}

		try{
			// tries to update a record that not exists id database. The expected result is IdNotFoundException
			java.sql.Date dateToExpire = new java.sql.Date(new java.util.Date().getTime()); 
			java.sql.Time timeToExpire = new java.sql.Time(new java.util.Date().getTime() + 2*1000*60*60);
			
			sessionKeyDao.update("0004", "9512fa0b68a18832146849d8f6d2e9f2", dateToExpire, timeToExpire);
		} //expected exceptions
		  catch (IdNotFoundException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
		} //unexpected exceptions
		  catch (SessionKeyNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (IdNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}  catch (ExpirationDateNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}
		
		try{
			// tries to update a record of database, but not inform the expiration date. The expected result is ExpirationDateNotInformedException
			sessionKeyDao.update("0004", "9512fa0b68a18832146849d8f6d2e9f2", null, null);
		} //expected exception
		  catch (ExpirationDateNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
		} //unexpected exceptions
		  catch (SessionKeyNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (IdNotFoundException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (IdNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}
		
		try{
			// tries to update a record of database. The expected result is successfull update
			java.sql.Date dateToExpire = new java.sql.Date(new java.util.Date().getTime());
			java.sql.Time timeToExpire = new java.sql.Time(new java.util.Date().getTime() + 2*1000*60*60);
			
			sessionKeyDao.update("0004", "9512fa0b68a18832146849d8f6d2e9f2", dateToExpire, timeToExpire);
		} catch (SessionKeyNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (IdNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (IdNotFoundException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (ExpirationDateNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}
	}
	
	/* tests the deletion method in the different situations, for example try to delete a record that does 
	not exist, delete a record properly, or call the method with null parameter */
	public void testDelete(){
		// tries to delete an record that not exists in database. The expected result is IdNotFoundException 
		try {
			sessionKeyDao.delete("0009");
		} //expected exception
		  catch(IdNotFoundException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
		} catch(IdNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}
		
		// tries to execute the method delete, but not inform the id. The expected result is IdNotInformedException 
		try {
			sessionKeyDao.delete(null);
		} //expected exception
		  catch(IdNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
		} //unexpected exception
		  catch(IdNotFoundException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}
		  
	    // executes successfully the deletion
		try {
			sessionKeyDao.delete("0004");
		} catch(IdNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch(IdNotFoundException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}  
	}
	
	/* tests the method in the different situations, for example try to find a record that does 
	not exist, find a record properly, call the method with null parameter, or try to find an
	id duplicated in database */
	public void testFindById(){

		// tries to find an id that exists in database and is unique. The expected result is succeess.
		try{
			sessionKeyDao.insert("0004", "9512fa0b68a18832146849d8f6d2e9f2");
			assertNotNull(sessionKeyDao.findById("0004"));
		} catch (IdNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (SessionKeyNotInformedException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (SQLException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (DuplicateIdException e){
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}
		
		// tries to find an id that not exists in database. The expected result is that the method returns null 
		try{
			assertNull(sessionKeyDao.findById("0010"));
		} catch (IdNotInformedException e) {
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (DuplicateIdException e) {
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (SQLException e) {
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}
		
		// tries to execute the method when the is null. The expected result is IdNotInformedException 
		try{
			sessionKeyDao.findById(null);
		} //expected exception
		  catch (IdNotInformedException e) {
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
		} //unexpected exceptions
		  catch (DuplicateIdException e) {
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (SQLException e) {
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}
		
		// find an duplicated id in database. The expected result is DuplicateIdException
		try{
			// manually insert a record whose id already exists in database
			int TIME_TO_LIVE = 2;
			String TABLE_NAME = "keySessionData";
			String ID_COLUMN_NAME = "id";
			String DATE_COLUMN_NAME = "expirationDate";
			String SESSIONKEY_COLUMN_NAME = "sessionKey";
			
			java.util.Date today = new java.util.Date();
			java.sql.Date expirationDate = new java.sql.Date(today.getTime() + ((1000*60*60)*TIME_TO_LIVE));
			
			SessionKeyDaoHSQLDB sessionKeyDaoHSQLDB = new SessionKeyDaoHSQLDB(); 
			sessionKeyDao = sessionKeyDaoHSQLDB;
			Connection con = sessionKeyDaoHSQLDB.connect();
			
			String query = "insert into " + TABLE_NAME + 
			"(" + ID_COLUMN_NAME + ", " + DATE_COLUMN_NAME + ", " + SESSIONKEY_COLUMN_NAME + ") values (?, ?, ?)";
			
			PreparedStatement stm = con.prepareStatement(query);
			
			stm.setString(1, "0004");
			stm.setDate(2, expirationDate);
			stm.setString(3, "5a68ca308ed8611b68640634514cdf00");
			
			//execute insertion
			stm.executeUpdate();
			stm.close();
			// closes connection
			con.close();
			
			// find duplicated id. The expected result is DuplicateIdException 
			sessionKeyDao.findById("0004");
			
		} //expected exception
		  catch (DuplicateIdException e) {
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
		} //unexpected exceptions
		  catch (IdNotInformedException e) {
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		} catch (SQLException e) {
			Logger.getLogger(TestAuthentication.class.getName()).log(Level.INFO, e.toString(), e);
			fail();
		}
	}
}
