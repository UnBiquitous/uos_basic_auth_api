package br.unb.unbiquitous.ubiquitos.authentication.exception;

public class InvalidHMACException extends Exception {
	private static final long serialVersionUID = -941556828696519186L;

	public String toString() {
	    return "Lack of integrity in message. HMAC does not match the received message";
	  }
}
