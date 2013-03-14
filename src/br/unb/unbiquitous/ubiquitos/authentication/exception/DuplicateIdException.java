package br.unb.unbiquitous.ubiquitos.authentication.exception;

public class DuplicateIdException extends Exception{
	private static final long serialVersionUID = 5037891843513089741L;

	public String toString() {
	    return "id duplicated in database";
	  }
}