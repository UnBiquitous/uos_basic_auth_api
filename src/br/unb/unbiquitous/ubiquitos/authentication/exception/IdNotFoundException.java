package br.unb.unbiquitous.ubiquitos.authentication.exception;

public class IdNotFoundException extends Exception{
	private static final long serialVersionUID = -6358433559902232938L;

	public String toString() {
	    return "id not found in database";
	  }
}
