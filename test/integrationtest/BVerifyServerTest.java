package integrationtest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Assert;
import org.junit.Test;

import bench.MockTester;
import crpyto.CryptographicDigest;

public class BVerifyServerTest {
	private static final Logger logger = Logger.getLogger(BVerifyServerTest.class.getName());
	private static final byte[] START_VALUE = CryptographicDigest.hash("STARTING".getBytes());

	@Test
	public void testSingleADSUpdatesEveryEntryOnce() {
		// test has 175 distinct ADSes, all of which 
		// are updated once!
		int nClients = 10;
		int nClientsPerAdsMax = 3;
		int nADS = 100;
		int batchSize = 1;
		MockTester tester = new MockTester(nClients, nClientsPerAdsMax, nADS, batchSize, START_VALUE, true);
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
	public void testSingleADSUpdatesEveryEntryOnceBatched() {
		int nClients = 10;
		int nClientsPerAdsMax = 3;
		int nADS = 100;
		// batch size is now 25!
		int batchSize = 25;
		MockTester tester = new MockTester(nClients, nClientsPerAdsMax, nADS, batchSize, START_VALUE, true);
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
	public void testSingleADSUpdatesMultipleTimes() {
		// test has 175 distinct ADSes, all of which 
		// are updated three times, 
		// but the updates are shuffled 
		// so the order is random
		int nClients = 10;
		int nClientsPerAdsMax = 3;
		int batchSize = 1;
		int nADS = 100;
		MockTester tester = new MockTester(nClients, nClientsPerAdsMax, nADS, batchSize, START_VALUE, true);
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
	
	@Test
	public void testUpdateMultipleTimesBatched() {
		// test has 175 distinct ADSes, all of which 
		// are updated three times, 
		// but the updates are shuffled 
		// so the order is random
		int nClients = 10;
		int nClientsPerAdsMax = 3;
		int batchSize = 25;
		int nADS = 100;
		MockTester tester = new MockTester(nClients, nClientsPerAdsMax, nADS, batchSize, START_VALUE, true);
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
	
	@Test
	public void testMultipleADSUpdates() {
		int nClients = 10;
		int nClientsPerAdsMax = 3;
		int batchSize = 1;
		int nADS = 100;
		MockTester tester = new MockTester(nClients, nClientsPerAdsMax, nADS, batchSize, START_VALUE, true);
		List<byte[]> adsIds = tester.getADSIds();
		// updates
		List<Map.Entry<byte[], byte[]>> updates = new ArrayList<>();
		for(int i = 0; i < 10; i++) {
			byte[] newValue = CryptographicDigest.hash(("some new value"+i).getBytes());
			updates.add(Map.entry(adsIds.get(i), newValue));
		}
		boolean updateAccepted = tester.doUpdate(updates);
		Assert.assertTrue("Update should be accepted", updateAccepted);
		boolean proofsValid = tester.getAndCheckProofs();
		Assert.assertTrue("Proofs should be valid", proofsValid);	
	}
	
	@Test
	public void testMultipleADSUpdatesMultipleUpdates() {
		int nClients = 10;
		int nClientsPerAdsMax = 3;
		int batchSize = 1;
		int nADS = 100;
		MockTester tester = new MockTester(nClients, nClientsPerAdsMax, nADS, batchSize, START_VALUE, true);
		List<byte[]> adsIds = tester.getADSIds();
		
		List<Map.Entry<byte[], byte[]>> updates = new ArrayList<>();
		final int updateSize = 5;
		int update = 0;
		int salt = 0;
		for(byte[] adsId : adsIds) {
			byte[] newValue = CryptographicDigest.hash(("some new value"+salt).getBytes());
			updates.add(Map.entry(adsId, newValue));
			update++;
			salt++;
			if(updateSize == update) {
				boolean updateAccepted = tester.doUpdate(updates);
				Assert.assertTrue("Update should be accepted", updateAccepted);
				boolean proofsValid = tester.getAndCheckProofs();
				Assert.assertTrue("Proofs should be valid", proofsValid);	
				update = 0;
				updates.clear();
			}			
		}
		
	}	
	
}
