package br.unb.unbiquitous.ubiquitos.authentication;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Calendar;
import java.util.logging.Level;
import java.util.logging.Logger;

import br.unb.unbiquitous.ubiquitos.authentication.exception.DuplicateIdException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.ExpirationDateNotInformedException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.IdNotFoundException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.IdNotInformedException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.SessionKeyNotInformedException;


/** 
 * Class to manipulate the test database. Implements the methods defined in AuthenticationDao
 * interface: findByHashId, delete, update and insert.
 * The parameters needed to initialize and manipulate database are difined as class constants.
 * This parameters constants: url of database, user, password, table name and column names.
 * */
public class SessionKeyDaoHSQLDB implements SessionKeyDao{
	
	private static Logger logger = Logger.getLogger(SessionKeyDaoHSQLDB.class.getName());
	
	private static final String JDBC_DRIVER = "org.hsqldb.jdbcDriver";
	private static final String BD_URL = "jdbc:hsqldb:mem:";
	private static final String USER = "sa";
    private static final String PASSWORD = "";
    private static final String DATABASE = "memoryBD";
	String TABLE_NAME = "keySessionData";
	String ID_COLUMN_NAME = "id";
	String DATE_COLUMN_NAME = "expirationDate";
	String TIME_COLUMN_NAME = "expirationTime";
	String SESSIONKEY_COLUMN_NAME = "sessionKey";
    
    
    /** 
     * Creates a table to save device's authentication data.
     * */
    public SessionKeyDaoHSQLDB(){
    	Connection con;
    	
    	try {
        	Class.forName(JDBC_DRIVER);
        	
        	// connects to database
			con = connect(); 
			
			// Checks if table already exists.
	    	String [] types = new String[1];
	    	types[0] = "TABLE";
	    	DatabaseMetaData md = con.getMetaData();  
	    	
	    	// checks if the table already exists
	    	ResultSet rs = md.getTables(null, null, TABLE_NAME.toUpperCase(), types);

	    	// if the table not exists yet it is created
	    	if (!rs.next()) {
	    		PreparedStatement pstmt = con.prepareStatement("create table " + TABLE_NAME + "(" + ID_COLUMN_NAME + " varchar(40), " + DATE_COLUMN_NAME + " date, " + TIME_COLUMN_NAME + " time, " + SESSIONKEY_COLUMN_NAME + " varchar(32));");
	    		pstmt.executeUpdate();  
	    	}

	    	// closes the connection
	    	con.close();
		
    	} catch (ClassNotFoundException e) {
			logger.log(Level.SEVERE, "", e);
		} catch (SQLException e) {
			logger.log(Level.SEVERE, "", e);
		} 
    }

    
    /** 
     * Access the database and find the device that has a given hash(id).
     * If there are more than one device with the same hash(id) returns a error.
     * If there are no device with given hash(id) returns null
     * 
     * @param hashId - hash(id) of the device
     * @return authenticationData - object with id, hashId and key retrieved from database.
     * */
	public SessionData findById (String id) throws SQLException, DuplicateIdException, IdNotInformedException {   

		// creates an object to store the result
		SessionData sessionData = new SessionData();
		ResultSet resultSet = null;
		Connection con;
		
		try {
			if (id != null && !id.isEmpty()){
				
				//connects to database
				con = connect();
	            PreparedStatement pstmt = con.prepareStatement(
	            		"select " + ID_COLUMN_NAME + ", " + DATE_COLUMN_NAME + ", " + TIME_COLUMN_NAME + ", " + SESSIONKEY_COLUMN_NAME + " from " + TABLE_NAME + " where " + ID_COLUMN_NAME + " = ?");
	
	            pstmt.setString(1, id);
	            // executes search and stores result in resultSet
	            resultSet = pstmt.executeQuery();
	
	            // moves the cursor to the first line of the result (if this line exists)
	            resultSet.next();
	            // if there are first line
	            if (resultSet.getRow() == 1) {
	            	
	            	sessionData.setId(resultSet.getString(ID_COLUMN_NAME));
	            	sessionData.setSessionKey(resultSet.getString(SESSIONKEY_COLUMN_NAME));
	            	sessionData.setExpirationDate((java.util.Date)(resultSet.getDate(DATE_COLUMN_NAME)));
	            	sessionData.setExpirationTime(resultSet.getTime(TIME_COLUMN_NAME));
	            	
	                // if there are more than one line with the same hashId in database throw DuplicateIdException
	                if (resultSet.next()!= false){
	            		throw new DuplicateIdException();
	                }
	            // if there are no lines in database with the given id, returns null 
	            } else {
	                if (resultSet.getRow() == 0){
	                	return null;
	                }
	            }
	            
	            // closes connection
	            con.close();
			} else {
				throw new IdNotInformedException();
			}
        }  catch (SQLException ex) {
            Logger.getLogger(AuthenticationHandler.class.getName()).log(Level.SEVERE, null, ex);
            throw new SQLException();
        }
		return sessionData;
	}
	
	
	/** 
	 * Deletes from database the device that has a given id.
	 * 
	 * @param id - id of the device to be deleted.
	 * */
	public void delete (String id) throws IdNotFoundException, IdNotInformedException{
		Connection con;
	
		try {
			if (id != null && !id.isEmpty()){
				if (findById(id) != null){
					// connects to database
					con = connect();
					String sql = "";
					PreparedStatement stm = con.prepareStatement(sql);
					sql = "delete from " + TABLE_NAME + " where " + ID_COLUMN_NAME + " like ?";
					stm = con.prepareStatement(sql);
					stm.setString(1,id);
					// executes deletion
					stm.executeUpdate();
					stm.close();
					//closes connection
					con.close();
				} else {
					throw new IdNotFoundException();
				}
			} else{
				throw new IdNotInformedException();
			}
		} catch (SQLException e) {
			logger.log(Level.SEVERE, "", e);
		} catch (DuplicateIdException e){
			logger.log(Level.SEVERE, "", e);
		}
	}

	
	/** 
	 * Deletes from database all devices.
	 * 
	 * */
	public void deleteAll () throws IdNotFoundException, IdNotInformedException{
		Connection con;
		try{
			con = connect();
			String sql = "";
			PreparedStatement stm = con.prepareStatement(sql);
			sql = "delete from " + TABLE_NAME;
			stm = con.prepareStatement(sql);
			// executes deletion
			stm.executeUpdate();
			stm.close();
			//closes connection
			con.close();
		} catch (SQLException e){
			logger.log(Level.SEVERE, "", e);
		}
	}
	
	
	/** 
	 * Updates a device's key in the database.
	 * 
	 * @param id - id of the device whose key will be updated.
	 * @param key - the new key
	 * */
	public void update (String id, String newSessionKey, java.sql.Date newExpirationDate, java.sql.Time newExpirationTime) 
	throws IdNotFoundException, IdNotInformedException, SessionKeyNotInformedException, ExpirationDateNotInformedException {

		try {
			Connection con;
			if (id != null && !id.isEmpty()){
				if (newSessionKey != null && !newSessionKey.isEmpty()){
					if (newExpirationDate != null){
						if (findById(id) != null){
							// connect to database
							con = connect();
							
							String query = "update " + TABLE_NAME + " set " + SESSIONKEY_COLUMN_NAME + " = ?, " 
								+ DATE_COLUMN_NAME + " = ?," + TIME_COLUMN_NAME + " = ?"
								+ " where " + ID_COLUMN_NAME + " like ?";
							
							PreparedStatement stm = con.prepareStatement(query);
							
							stm.setString(1, newSessionKey);
							stm.setDate(2, newExpirationDate);
							stm.setTime(3, newExpirationTime);
							stm.setString(4, id);
							
							//execute insertion
							stm.executeUpdate();
							stm.close();
							// closes connection
							con.close();
						} else {
			    			throw new IdNotFoundException();
			    		}
					} else{
						throw new ExpirationDateNotInformedException();
					}
				} else{
					throw new SessionKeyNotInformedException();
				}
    		} else{
    			throw new IdNotInformedException();
    		}
    			
		} catch (SQLException e) {
				logger.log(Level.SEVERE, "", e);
		} catch (DuplicateIdException e) {
				logger.log(Level.SEVERE, "", e);
		} 
	}

	
	/** 
	 * Inserts a record to database. Each record has id, key and hash(id), informed as parameters.
	 * 
	 * @param id - device's identificator
	 * @param timeToLive - number of hours that the session key will be used
	 * @param sessionKey - session key
	 * */
	public void insert (String id, String sessionKey) throws IdNotInformedException, SessionKeyNotInformedException {
		
		//constant that defines the time that the session key will be valid (in hours)
		int TIME_TO_LIVE = 2;
		Connection con;

		java.util.Date today = new java.util.Date();
		java.sql.Date expirationDate = new java.sql.Date(today.getTime());
		
		java.sql.Time expirationTime = new java.sql.Time(new java.util.Date().getTime()+ ((1000*60*60)*TIME_TO_LIVE));
		
    	try {
    		if (findById(id) == null){
    			if (id != null && !id.isEmpty()){
    				if (sessionKey != null && !sessionKey.isEmpty()){
			    		// connect to database
						con = connect();
						String query = "insert into " + TABLE_NAME + 
						"(" + ID_COLUMN_NAME + ", " + DATE_COLUMN_NAME + ", " + TIME_COLUMN_NAME + ", " + SESSIONKEY_COLUMN_NAME + ") values (?, ?, ?, ?)";
						
						PreparedStatement stm = con.prepareStatement(query);
						
						stm.setString(1, id);
						stm.setDate(2, expirationDate);
						stm.setTime(3, expirationTime);
						stm.setString(4, sessionKey);
						
						//execute insertion
						stm.executeUpdate();
						
						stm.close();
						// closes connection
						con.close();
    				}
    				else{
    					throw new SessionKeyNotInformedException(); 
    				}
    			} 
    			else{
    				throw new IdNotInformedException(); 
    			}
    		}
    		// if the device is already in database, updates sessionKey and expiration date
    		else {
    			try{
    				update(id, sessionKey, expirationDate, expirationTime);
    			} catch (IdNotFoundException e){
    				logger.log(Level.SEVERE, "", e);
    			} catch (ExpirationDateNotInformedException e){
    				logger.log(Level.SEVERE, "", e);
    			}
    		}
		} catch (SQLException e) {
			logger.log(Level.SEVERE, "", e);
		} catch (DuplicateIdException e){
			logger.log(Level.SEVERE, "", e);
		}
	}

	
    /** 
     * Access the database and find the device that has a given hash(id).
     * If there are more than one device with the same hash(id) returns a error.
     * If there are no device with given hash(id) returns null
     * 
     * @param hashId - hash(id) of the device
     * @return authenticationData - object with id, hashId and key retrieved from database.
     * */
	public SessionData findAll() throws SQLException {   

		// creates an object to store the result
		SessionData sessionData = new SessionData();
		ResultSet resultSet = null;
		Connection con;
		
		try {
				//connects to database
				con = connect();
	            PreparedStatement pstmt = con.prepareStatement(
	            "select " + ID_COLUMN_NAME + ", " + DATE_COLUMN_NAME + ", " + TIME_COLUMN_NAME + ", " + SESSIONKEY_COLUMN_NAME + " from " + TABLE_NAME);
	
	            // executes search and stores result in resultSet
	            resultSet = pstmt.executeQuery();
	            
	            // moves the cursor to the first line of the result (if this line exists)
	            resultSet.next();
	            // if there are first line
	            if (resultSet.getRow() > 0) {
	            	do{
		            	sessionData.setId(resultSet.getString(ID_COLUMN_NAME));
		            	sessionData.setSessionKey(resultSet.getString(SESSIONKEY_COLUMN_NAME));
		            	sessionData.setExpirationDate((java.util.Date)(resultSet.getDate(DATE_COLUMN_NAME)));
		            	sessionData.setExpirationTime(resultSet.getTime(TIME_COLUMN_NAME));
		                
	            	} while (resultSet.next()!= false);
	            // if there are no lines in database with the given id, returns null 
	            } else {
	                if (resultSet.getRow() == 0){
	                	return null;
	                }
	            }
	            
	            // closes connection
	            con.close();
        }  catch (SQLException ex) {
            Logger.getLogger(AuthenticationHandler.class.getName()).log(Level.SEVERE, null, ex);
            throw new SQLException();
        }
		return sessionData;
	}

	
	@SuppressWarnings("deprecation")
	public boolean isBeforeToday(java.sql.Time time, java.util.Date date){

		java.util.Date today = new java.util.Date();
		
		Calendar calendar = Calendar.getInstance();
		calendar.set(date.getYear(), date.getMonth(), date.getDate(), time.getHours(), time.getMinutes(), time.getSeconds());
		
		Calendar todayCalendar = Calendar.getInstance();
		todayCalendar.set(today.getYear(), today.getMonth(), today.getDate(), today.getHours(), today.getMinutes(), today.getSeconds());
		
		if (todayCalendar.before(calendar)){
			return true;
		} else {
			return false;
		}
	}
	
	
	/** 
	 * Connects to database. The parameters url, user and password are constants initialized in the constructor.
	 * 
	 * @return database connection
	 * */
    protected Connection connect() throws SQLException {
    	String database = DATABASE;
    	String user = USER;
    	String password = PASSWORD;
    	return DriverManager.getConnection(BD_URL + database , user ,password);
    }
    
    public static void main(String [] args){
    	
    	
    }
    
}
