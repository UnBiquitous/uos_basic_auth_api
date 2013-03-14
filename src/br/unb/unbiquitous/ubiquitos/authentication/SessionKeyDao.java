package br.unb.unbiquitous.ubiquitos.authentication;

import java.sql.SQLException;

import br.unb.unbiquitous.ubiquitos.authentication.exception.DuplicateIdException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.ExpirationDateNotInformedException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.IdNotFoundException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.IdNotInformedException;
import br.unb.unbiquitous.ubiquitos.authentication.exception.SessionKeyNotInformedException;

public interface SessionKeyDao {

	public SessionData findById (String id)  throws SQLException, DuplicateIdException, IdNotInformedException;
	
	public void delete (String id) throws IdNotFoundException, IdNotInformedException;
	
	public void update (String id, String newSessionKey, java.sql.Date expirationDate, java.sql.Time expirationTime) throws IdNotFoundException, IdNotInformedException, SessionKeyNotInformedException, ExpirationDateNotInformedException;
	
	public void insert (String id, String sessionKey) throws IdNotInformedException, SessionKeyNotInformedException;
	
	public boolean isBeforeToday(java.sql.Time time, java.util.Date date);
}

