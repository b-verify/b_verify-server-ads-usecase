package server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import mpt.core.InvalidSerializationException;
import mpt.core.Utils;
import mpt.set.AuthenticatedSetServer;
import mpt.set.MPTSetFull;

/**
 * Client adses can be arbitrary 
 * authenticated data structures. 
 * 
 * For this example clients use authenticated
 * sets. 
 * 
 * This class is responsible updating 
 * these datastructures on the server side 
 * and returning them, or views
 * of them to clients.
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
	private static final String TMP = "TMP";
	private final List<byte[]> adsToCommit;
	
	public ClientADSManager(String base) {
		this.base = base;
		this.adsToCommit = new ArrayList<>();
	}
	
	/**
	 * Return the authenticated set identified by  
	 * adsKey if it exists or an empty authenticated set 
	 * if it does not
	 * @param adsKey - the identifying id for the ads 
	 * @return the authenticated set if it exists or an 
	 * empty set
	 */
	public AuthenticatedSetServer getADS(final byte[] adsKey) {
		String fileName = Utils.byteArrayAsHexString(adsKey);
		try {
			File f = new File(base+fileName);
			FileInputStream fis = new FileInputStream(f);
			byte[] encodedAds = new byte[(int) f.length()];
			fis.read(encodedAds);
			fis.close();
			MPTSetFull mptSet = MPTSetFull.deserialize(encodedAds);
			return mptSet;
		}catch(InvalidSerializationException e) {
			throw new RuntimeException("data on disk is corrupted");
		} catch (IOException e) {
			return new MPTSetFull();
		}
	}
		
	/**
	 * Save an authenticated set identified by 
	 * adsKey. 
	 * @param ads - the authenticated set to save
	 * @param adsKey - the id of the authenticated 
	 * set to save.
	 */
	public void saveADS(final AuthenticatedSetServer ads,final byte[] adsKey) {
		String fileName = Utils.byteArrayAsHexString(adsKey);
		byte[] serialized = ads.serialize().toByteArray();
		try {
			File f = new File(base+fileName);
			FileOutputStream fos = new FileOutputStream(f);
			fos.write(serialized);
			fos.close();
		}catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	public boolean preCommit(final AuthenticatedSetServer ads, final byte[] adsKey) {
		String fileName = base+Utils.byteArrayAsHexString(adsKey)+TMP;
		byte[] serialized = ads.serialize().toByteArray();
		try {
			File f = new File(fileName);
			if(f.exists()) {
				return false;
			}
			FileOutputStream fos = new FileOutputStream(f);
			fos.write(serialized);
			fos.close();
			// add the key to the list
			this.adsToCommit.add(adsKey);
			return true;
		}catch(Exception e) {
			return false;
		}
	}
	
	private void commitADS(final byte[] adsKey) {
		String currentFile = base+Utils.byteArrayAsHexString(adsKey);
		String newFile = base+Utils.byteArrayAsHexString(adsKey)+TMP;
		File currentf = new File(currentFile);
		File newf = new File(newFile);
		// delete the existing ads
		currentf.delete();
		// replace with the new one
		newf.renameTo(currentf);
	}
	
	private void abortADS(final byte[] adsKey) {
		String newFile = base+Utils.byteArrayAsHexString(adsKey)+TMP;
		File newf = new File(newFile);
		newf.delete();
	}
	
	public void commit() {
		for(final byte[] adsKey : this.adsToCommit) {
			this.commitADS(adsKey);
		}
		this.adsToCommit.clear();
	}
	
	public void abort() {
		for(final byte[] adsKey : this.adsToCommit) {
			this.abortADS(adsKey);
		}
		this.adsToCommit.clear();
	}
	
	public static void main(String[] args) {
		ClientADSManager adsManager = new ClientADSManager("/home/henryaspegren/eclipse-workspace/b_verify-server/mock-data/client-ads/");
		
		byte[] key1 = Utils.getKey(1);
		byte[] key2 = Utils.getKey(2);
		byte[] key3 = Utils.getKey(3);

		
		MPTSetFull a = Utils.makeMPTSetFull(100, "test");
		MPTSetFull b = Utils.makeMPTSetFull(100, "testb");
		MPTSetFull c = Utils.makeMPTSetFull(100, "testc");

		adsManager.preCommit(a, key1);
		adsManager.preCommit(b, key2);
		adsManager.preCommit(c, key3);
		
		adsManager.commit();
		
		AuthenticatedSetServer aFromBytes = adsManager.getADS(key1);
		AuthenticatedSetServer bFromBytes = adsManager.getADS(key2);
		AuthenticatedSetServer cFromBytes = adsManager.getADS(key3);
		
		System.out.println(Arrays.equals(aFromBytes.commitment(), a.commitment()));
		System.out.println(Arrays.equals(bFromBytes.commitment(), b.commitment()));
		System.out.println(Arrays.equals(cFromBytes.commitment(), c.commitment()));


		c.insert(Utils.getValue(1, "other"));
		
		adsManager.preCommit(c, key3);
		adsManager.commit();

		cFromBytes = adsManager.getADS(key3);
		System.out.println(Arrays.equals(cFromBytes.commitment(), c.commitment()));

		c.delete(Utils.getValue(1, "other"));
		adsManager.preCommit(c, key3);
		adsManager.abort();
		
		cFromBytes = adsManager.getADS(key3);
		System.out.println(Arrays.equals(cFromBytes.commitment(), c.commitment()));

	}
	
}
