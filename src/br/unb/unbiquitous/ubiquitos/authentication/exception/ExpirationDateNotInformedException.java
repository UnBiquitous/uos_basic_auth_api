package br.unb.unbiquitous.ubiquitos.authentication.exception;

public class ExpirationDateNotInformedException extends Exception{
	private static final long serialVersionUID = 2679343095715140935L;

	public String toString() {
	    return "expiration date not informed.";
	  }
}
