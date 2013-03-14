package br.unb.unbiquitous.ubiquitos.authentication.exception;

public class InvalidHashIdException extends Exception {
	private static final long serialVersionUID = 8606766101328037487L;

	public String toString() {
	    return "Different ids in hash(id) and Eka(id), or incorrect key";
	    }
	}
