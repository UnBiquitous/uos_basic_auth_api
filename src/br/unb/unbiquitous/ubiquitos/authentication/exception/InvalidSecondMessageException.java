package br.unb.unbiquitous.ubiquitos.authentication.exception;

public class InvalidSecondMessageException extends Exception{
	private static final long serialVersionUID = 8655992521451105229L;

	public String toString() {
	    return "Incorrect id, ra or ra' in second message.";
	  }
}
