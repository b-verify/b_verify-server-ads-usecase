package server;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import mpt.core.InvalidSerializationException;
import mpt.core.Utils;
import mpt.set.AuthenticatedSetServer;
import mpt.set.MPTSetFull;
import pki.Account;
import pki.PKIDirectory;

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

	private final String clientADSdir;

	private final Map<byte[], ClientADS> adsIdToClientADS;

	public ClientADSManager(PKIDirectory pki, String clientADSdir) {
		this.clientADSdir = clientADSdir;
		this.adsIdToClientADS = new HashMap<>();
		
		// get the adskey and record which clients
		// care about each adskey
		Map<byte[], Set<Account>> adsIdToClients = new HashMap<>();
		Set<Account> accounts = pki.getAllAccounts();
		for(Account a : accounts) {
			Set<byte[]> adsKeys = a.getADSKeys();
			for(byte[] adsKey : adsKeys) {
				Set<Account> accs = adsIdToClients.get(adsKey);
				if(accs == null) {
					accs = new HashSet<>();
				}
				accs.add(a);
				adsIdToClients.put(adsKey, accs);
			}
		}
		
		// now load the actual adses into memory
		for(byte[] adsKey : adsIdToClients.keySet()) {
			AuthenticatedSetServer mptSet = 
					ClientADSManager.loadADSFromFile(this.clientADSdir, adsKey);
			ClientADS clientADS = new ClientADS(adsIdToClients.get(adsKey), adsKey, mptSet);
			this.adsIdToClientADS.put(adsKey, clientADS);
		}		
	}

	public synchronized Set<byte[]> getAdsKeys(){
		// DANGER returning a mutable reference
		return this.adsIdToClientADS.keySet();
	}
	
	public synchronized Set<Account> getRelevantClients(final byte[] adsKey){
		// DANGER returning a mutable reference
		return this.adsIdToClientADS.get(adsKey).getOwners();
	}

	public static AuthenticatedSetServer loadADSFromFile(String clientADSDir, 
			final byte[] adsKey) {
		File adsFile = new File(clientADSDir+Utils.byteArrayAsHexString(adsKey));
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

	}

}
