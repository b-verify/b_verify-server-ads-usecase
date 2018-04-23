package server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import crpyto.CryptographicDigest;
import mpt.core.Utils;
import mpt.set.AuthenticatedSetServer;
import mpt.set.MPTSetFull;

/**
 * This class is responsible for managing 
 * client ads stored on the server. 
 * 
 * Currently this implementation just 
 * loads and saves the ADSes from disk. 
 * More complex and optimized schemes 
 * are possible.
 * 
 * @author henryaspegren
 */
public class ClientADSManager {

	private final String base;
	
	public ClientADSManager(String base) {
		this.base = base;
	}
	
	/**
	 * Return the authenticated set identified by  
	 * adsKey if it exists or null if it does 
	 * @param adsKey - the identifying id for the ads 
	 * @return the authenticated set if it exists or null
	 * if it does not exist or is not serialized properly
	 */
	public AuthenticatedSetServer getADS(byte[] adsKey) {
		String fileName = Utils.byteArrayAsHexString(adsKey);
		try {
			File f = new File(base+fileName);
			FileInputStream fis = new FileInputStream(f);
			byte[] encodedAds = new byte[(int) f.length()];
			fis.read(encodedAds);
			fis.close();
			MPTSetFull mptSet = MPTSetFull.deserialize(encodedAds);
			return mptSet;
		}catch(Exception e) {
			return null;
		}
	}
	
	/**
	 * Save an authenticated set identified by 
	 * adsKey. 
	 * @param ads - the authenticated set to save
	 * @param adsKey - the id of the authenticated 
	 * set to save.
	 */
	public void saveADS(AuthenticatedSetServer ads, byte[] adsKey) {
		String fileName = Utils.byteArrayAsHexString(adsKey);
		byte[] serialized = ads.serialize();
		try {
			File f = new File(base+fileName);
			FileOutputStream fos = new FileOutputStream(f);
			fos.write(serialized);
			fos.close();
		}catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	public static void main(String[] args) {
		ClientADSManager adsManager = new ClientADSManager("/home/henryaspegren/eclipse-workspace/b_verify-server/mock-data/client-ads/");
		MPTSetFull set = Utils.makeMPTSetFull(100, "test");
		byte[] keyHash = CryptographicDigest.hash("some string".getBytes());
		adsManager.saveADS(set, keyHash);
		
		AuthenticatedSetServer fromBytes = adsManager.getADS(keyHash);
		System.out.println(Utils.byteArrayAsHexString(fromBytes.commitment()));
		System.out.println(Utils.byteArrayAsHexString(set.commitment()));
		
		byte[] toInsert = "other".getBytes();
		set.insert(toInsert);
		
		adsManager.saveADS(set, keyHash);
		AuthenticatedSetServer fromBytes2 = adsManager.getADS(keyHash);
		System.out.println(Utils.byteArrayAsHexString(fromBytes2.commitment()));
		System.out.println(Utils.byteArrayAsHexString(set.commitment()));
		
		AuthenticatedSetServer doesNotExist = adsManager.getADS("1".getBytes());
		System.out.println(doesNotExist);
	}
	
}
