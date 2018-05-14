package integrationtest;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Assert;
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
	
		boolean accepetedUpdate1 = tester.doUpdate(adsIds.get(0), newValue);
		boolean proofsUpdate1 = tester.getAndCheckProofs();
		Assert.assertTrue("Update # 1 should be accepted", accepetedUpdate1);
		Assert.assertTrue("Proof for update # 1 should be accepted", proofsUpdate1);
		
		logger.log(Level.INFO, "UPDATING ADS ID: "+Utils.byteArrayAsHexString(adsIds.get(1)));
		boolean accepetedUpdate2 = tester.doUpdate(adsIds.get(1), newValue);
		boolean proofsUpdate2 = tester.getAndCheckProofs();
		Assert.assertTrue("Update # 2 should be accepted", accepetedUpdate2);
		Assert.assertTrue("Proof for update # 2 should be accepted", proofsUpdate2);
	}
	
	
}
