package integrationtest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Assert;
import org.junit.Test;

import crpyto.CryptographicDigest;

public class BVerifyServerTest {
	private static final Logger logger = Logger.getLogger(BVerifyServerTest.class.getName());
	
	@Test
	public void testUpdateEveryEntryOnce() {
		// test has 175 distinct ADSes, all of which 
		// are updated once!
		Tester tester = new Tester(10, 3);
		List<byte[]> adsIds = tester.getADSIds();
		logger.log(Level.INFO, "testing updating each entry once, total updates : "+adsIds.size());
		byte[] newValue = CryptographicDigest.hash("some new value".getBytes());
		for(byte[] adsId : adsIds) {
			boolean updateAccepted = tester.doUpdate(adsId, newValue);
			Assert.assertTrue("Update should be accepted", updateAccepted);
			boolean proofsValid = tester.getAndCheckProofs();
			Assert.assertTrue("Proofs should be valid", proofsValid);
		}
	}
	
	@Test
	public void testUpdateMultipleTimes() {
		// test has 175 distinct ADSes, all of which 
		// are updated three times, 
		// but the updates are shuffled 
		// so the order is random
		Tester tester = new Tester(10, 3);
		List<byte[]> adsIds = tester.getADSIds();
		List<byte[]> adsIdsToUpdate = new ArrayList<>(adsIds);
		adsIdsToUpdate.addAll(new ArrayList<>(adsIds));
		adsIdsToUpdate.addAll(new ArrayList<>(adsIds));
		logger.log(Level.INFO, "testing updates multiple times, total updates: "+adsIdsToUpdate.size());
		Collections.shuffle(adsIdsToUpdate);
		int i = 0;
		for(byte[] adsId : adsIdsToUpdate) {
			byte[] newValue = CryptographicDigest.hash(("some new value"+i).getBytes());
			boolean updateAccepted = tester.doUpdate(adsId, newValue);
			Assert.assertTrue("Update should be accepted", updateAccepted);
			boolean proofsValid = tester.getAndCheckProofs();
			Assert.assertTrue("Proofs should be valid", proofsValid);
			i++;
		}

		
	}
	
	
}
