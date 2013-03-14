package br.unb.unbiquitous.ubiquitos.authentication;

import java.sql.SQLException;

import br.unb.unbiquitous.ubiquitos.authentication.exception.DuplicateIdException;

 /** 
 * Interface that defines the methods to manipulate the device's database:
 * findByHashId, delete, update and insert.
 * */
public interface AuthenticationDao {

    /** 
     * Access the database and find the device that has a given hash(id).
     * If there are more than one device with the same hash(id) returns a error.
     * If there are no device with given hash(id) returns null
     * @param hashId - hash(id) of the device
     * @return authenticationData - object with id, hashId and key retrieved from database.
     * */
	public AuthenticationData findByHashId (String hashId)  throws SQLException, DuplicateIdException;
	
	/** 
	 * Deletes from database the device that has a given id.
	 * @param id - id of the device to be deleted.
	 * */
	public void delete (String id);
	
	/** 
	 * Updates a device's key in the database.
	 * @param id - id of the device whose key will be updated.
	 * @param key - the new key
	 * */
	public void update (String id, String newKey);
	
	/** 
	 * Inserts a record to database. Each record has id, key and hash(id), informed as parameters.
	 * @param id - device's identificator
	 * @param key - device's key
	 * @param hashId - hash(id)
	 * */
	public void insert (String id, String hashId , String key);

}
