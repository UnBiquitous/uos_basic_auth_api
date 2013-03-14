package br.unb.unbiquitous.ubiquitos.authentication;

/**
 * Class used to store device's data in objects, when they are get from database. Defines setters 
 * and getters to manipulate the device's attriutes.
 */
public class AuthenticationData {
	
    private String id;
    private String key;
    private String hashId;
    private String sessionKey;
    
    public String getSessionKey() {
		return sessionKey;
	}

	public void setSessionKey(String sessionKey) {
		this.sessionKey = sessionKey;
	}

	public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

	public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getHashId() {
		return hashId;
	}

	public void setHashId(String hashId) {
		this.hashId = hashId;
	}

}
