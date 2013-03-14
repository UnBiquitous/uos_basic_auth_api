package br.unb.unbiquitous.ubiquitos.authentication;

import junit.framework.Test;
import junit.framework.TestSuite;

public class TestSuiteAuthApi {
	public static Test suite() { 
        TestSuite suite = new TestSuite(TestSuiteAuthApi.class.getName());

        suite.addTestSuite(TestAuthentication.class);
        suite.addTestSuite(TestAuthenticationWithMessageTranslator.class);
        suite.addTestSuite(TestCipher.class);
        suite.addTestSuite(TestHMAC.class);
        suite.addTestSuite(TestSessionKeyDao.class);
        return suite; 
	}
}
