package br.unb.unbiquitous.ubiquitos.authentication.exception;

public class IdAlreadyExistsException extends Exception {
	private static final long serialVersionUID = -279983283014512708L;

	public String toString() {
	    return "impossible to insert. The id already exists in database.";
	  }
}
