package br.unb.unbiquitous.ubiquitos.authentication.exception;

public class ExpiredSessionKeyException extends Exception {
	private static final long serialVersionUID = 5264143638710193354L;

	public String toString() {
	    return "Expired session key. It is necessary to login again.";
	  }

}	
