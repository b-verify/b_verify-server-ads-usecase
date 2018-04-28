package server;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import mpt.core.InvalidSerializationException;
import mpt.core.Utils;
import mpt.set.AuthenticatedSetServer;
import mpt.set.MPTSetFull;

/**
 * This class is THREAD SAFE
 * 
 * Client ADSes can be arbitrary authenticated data structures.
 * 
 * For this example clients use authenticated sets.
 * 
 * This class is responsible updating these data structures on the server side
 * and returning them, or views of them to clients.
 * 
 * @author henryaspegren
 */
public class ClientADSManager {

	private final String base;

	private final Map<String, AuthenticatedSetServer> clientADSes;
	private final List<Map.Entry<String, AuthenticatedSetServer>> updates;

	public ClientADSManager(String base) {
		this.base = base;
		this.updates = new ArrayList<>();
		this.clientADSes = new HashMap<>();
		
		// load the current ADSes into memory
		File adsDirectory = new File(base);
		File[] adsFiles = adsDirectory.listFiles();
		for (File adsFile : adsFiles) {
			if (!adsFile.isFile()) {
				break;
			}
			String adsKey = adsFile.getName();
			try {
				FileInputStream fis = new FileInputStream(adsFile);
				byte[] encodedAds = new byte[(int) adsFile.length()];
				fis.read(encodedAds);
				fis.close();
				MPTSetFull mptSet = MPTSetFull.deserialize(encodedAds);
				this.clientADSes.put(adsKey, mptSet);
			} catch (InvalidSerializationException | IOException e) {
				e.printStackTrace();
				throw new RuntimeException("corrupted data");
			}
		}
		
	}
	
	/**
	 * Return the authenticated set identified by adsKey if it exists or an empty
	 * authenticated set if it does not.
	 * 
	 * @param adsKey
	 *            - the identifying id for the ads
	 * @return the authenticated set if it exists or an empty set
	 */
	public synchronized AuthenticatedSetServer getADS(final byte[] adsKey) {
		String key = Utils.byteArrayAsHexString(adsKey);
		if(this.clientADSes.containsKey(key)) {
			return this.clientADSes.get(key);
		}
		return new MPTSetFull();
	}

	/**
	 * Save an authenticated set identified by adsKey.
	 * 
	 * @param ads
	 *            - the authenticated set to save
	 * @param adsKey
	 *            - the id of the authenticated set to save.
	 */
	public synchronized void updateADS(final AuthenticatedSetServer ads, final byte[] adsKey) {
		String key = Utils.byteArrayAsHexString(adsKey);
		this.clientADSes.put(key, ads);
	}

	/**
	 * Stage an update to an ADS to be comitted. If
	 * commit() is called the update occurs and if abort() 
	 * is called it is deleted.
	 * 
	 * @param ads
	 * @param adsKey
	 * @return
	 */
	public synchronized boolean preCommit(final AuthenticatedSetServer ads, final byte[] adsKey) {
		String key = base + Utils.byteArrayAsHexString(adsKey);
		this.updates.add(Map.entry(key, ads));
		return true;
	}
	
	public synchronized void commit() {
		for(Map.Entry<String, AuthenticatedSetServer> update : this.updates) {
			this.clientADSes.put(update.getKey(), update.getValue());
		}
		this.updates.clear();
	}

	public synchronized void abort() {
		this.updates.clear();
	}
	
	public synchronized Set<String> getAdsKeys(){
		return this.clientADSes.keySet();
	}

	public static AuthenticatedSetServer loadADSFromFile(String base, 
			final byte[] adsKey) {
		File adsFile = new File(base+Utils.byteArrayAsHexString(adsKey));
		try {
			FileInputStream fis = new FileInputStream(adsFile);
			byte[] encodedAds = new byte[(int) adsFile.length()];
			fis.read(encodedAds);
			fis.close();
			MPTSetFull mptSet = MPTSetFull.deserialize(encodedAds);
			return mptSet;
		} catch (InvalidSerializationException | IOException e) {
			e.printStackTrace();
			throw new RuntimeException("corrupted data");
		}
	}
	
	public static void main(String[] args) {
		ClientADSManager adsManager = new ClientADSManager(
				"/home/henryaspegren/eclipse-workspace/b_verify-server/mock-data/client-ads/");
		System.out.println(adsManager.getAdsKeys().size());
	}

}
