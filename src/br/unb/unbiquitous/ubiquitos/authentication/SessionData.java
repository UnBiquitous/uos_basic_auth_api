package br.unb.unbiquitous.ubiquitos.authentication;

import java.util.Date;

public class SessionData {

	String id;
	Date expirationDate;
	java.sql.Time expirationTime;
	String sessionKey;

	public Date getExpirationDate() {
		return expirationDate;
	}
	public void setExpirationDate(Date expirationDate) {
		this.expirationDate = expirationDate;
	}
	public java.sql.Time getExpirationTime() {
		return expirationTime;
	}
	public void setExpirationTime(java.sql.Time expirationTime) {
		this.expirationTime = expirationTime;
	}
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public String getSessionKey() {
		return sessionKey;
	}
	public void setSessionKey(String sessionKey) {
		this.sessionKey = sessionKey;
	}
	
}
