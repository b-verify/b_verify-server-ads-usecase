package integrationtest;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Test;

import crpyto.CryptographicDigest;
import mpt.core.Utils;

public class BVerifyServerTest {
	private static final Logger logger = Logger.getLogger(BVerifyServerTest.class.getName());


	@Test
	public void runTest() throws Exception {
		Tester tester = new Tester(10, 3);
		java.util.List<byte[]> adsIds = tester.getADSIds();
		
		
		byte[] newValue = CryptographicDigest.hash("some new value".getBytes());
		
		
		logger.log(Level.INFO, "UPDATING ADS ID: "+Utils.byteArrayAsHexString(adsIds.get(0)));
		System.out.println("updated: "+tester.doUpdate(adsIds.get(0), newValue));
		System.out.println("proofs: "+tester.getAndCheckProofs());
		
		logger.log(Level.INFO, "UPDATING ADS ID: "+Utils.byteArrayAsHexString(adsIds.get(1)));
		System.out.println("updated: "+tester.doUpdate(adsIds.get(1), newValue));
		System.out.println("proofs: "+tester.getAndCheckProofs());
	}
	
	
}
