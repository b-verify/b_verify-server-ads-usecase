package server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.google.protobuf.ByteString;

import crpyto.CryptographicUtils;
import mpt.core.Utils;
import pki.Account;
import pki.PKIDirectory;
import serialization.generated.BVerifyAPIMessageSerialization.ADSModification;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import serialization.generated.BVerifyAPIMessageSerialization.Update;

public class StartingData implements Serializable {
	private static final long serialVersionUID = 1L;
	private static final Logger logger = Logger.getLogger(StartingData.class.getName());
	
	private final PKIDirectory pki;
	private final Set<PerformUpdateRequest> initializingUpdates;
	
	
	public StartingData(int nClients, int maxClientsPerADS, int nADSes,
			byte[] startingValue) {
		logger.log(Level.INFO, "generating starting data with "+nClients+
				" clients, "+nADSes+" (max "+maxClientsPerADS+" clients per ADS)");
		// (1) generate accounts 
		List<Account> accounts = PKIDirectory.generateRandomAccounts(nClients);		
		logger.log(Level.INFO, "..."+accounts.size()+" accounts generated");
		
		// (2) choose subsets, each subset is mapped to an ADS_ID
		List<List<Account>> adsAccounts = getSortedListsOfAccounts(accounts, maxClientsPerADS, 
				nADSes);
		logger.log(Level.INFO, "..."+accounts.size()+" subsets selected");
		
		// (3) create the initializing updates
		this.initializingUpdates = new HashSet<>();
		adsAccounts.parallelStream().forEach(accountsInADS -> {
			byte[] adsId = CryptographicUtils.listOfAccountsToADSId(accountsInADS);
			for(Account a : accountsInADS) {
				synchronized(a) {
					a.addADSKey(adsId);
				}
			}
			logger.log(Level.FINE, "{"+accountsInADS+"} -> "+Utils.byteArrayAsHexString(adsId));
			// create a request initializing this value
			PerformUpdateRequest initialUpdateRequest = createInitialUpdate(adsId, startingValue);
			synchronized(this.initializingUpdates) {
				this.initializingUpdates.add(initialUpdateRequest);
			}
		});
		logger.log(Level.INFO, "..."+this.initializingUpdates.size()+" initializing updates created");
		
		// (4) create the PKI
		this.pki = new PKIDirectory(accounts);
		logger.log(Level.INFO, "... pki created");
		logger.log(Level.INFO, "created: "+this.toString());
	}
	
	public PKIDirectory getPKI() {
		return this.pki;
	}
	
	public Set<PerformUpdateRequest> getInitialUpdates(){
		return new HashSet<>(this.initializingUpdates);
	}
	
	public void saveToFile(File f) {
		try {
			FileOutputStream fos = new FileOutputStream(f);
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			oos.writeObject(this);
			oos.close();
			fos.close();

		}catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	public static StartingData loadFromFile(File f) {
		try {
			FileInputStream fis = new FileInputStream(f);
			ObjectInputStream ois = new ObjectInputStream(fis);
			StartingData res = (StartingData) ois.readObject();
			ois.close();
			fis.close();
			return res;
		}catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	private static PerformUpdateRequest createInitialUpdate(byte[] adsId, byte[] startingValue) {
		return PerformUpdateRequest.newBuilder()
			.setUpdate(Update.newBuilder()
					.addModifications(ADSModification.newBuilder()
							.setAdsId(ByteString.copyFrom(adsId))
							.setNewValue(ByteString.copyFrom(startingValue)))
					.setValidAtCommitmentNumber(0))
			.build();
	}
	
	
	
	private static List<List<Account>> getSortedListsOfAccounts(List<Account> accounts, 
			int maxClientsPerADS, int nADSes){
		List<List<Account>> res = new ArrayList<>();
		for(int k = 1; k <= maxClientsPerADS; k++) {
			res.addAll(getSortedListsOfAccounts(accounts, k));
			logger.log(Level.INFO, "... "+res.size()+" sets of accounts generated so far");
		}
		if(res.size() < nADSes) {
			throw new RuntimeException("insufficient number of accounts");
		}
		return res.subList(0, nADSes);
	}
	
	private static List<List<Account>> getSortedListsOfAccounts(List<Account> accounts, int k){
		return processLargerSubsets(accounts, new ArrayList<>(), k, 0);
	}

	private static List<List<Account>> processLargerSubsets(List<Account> set, List<Account> subset, 
			int targetSize, int nextIndex) {
	    if (targetSize == subset.size()) {
	    	// also sort the subset
	    	Collections.sort(subset);
	    	return Arrays.asList(subset);
	    } else {
	    	List<List<Account>> subsets = new ArrayList<>();
	        for (int j = nextIndex; j < set.size(); j++) {
	        	List<Account> newSubset = new ArrayList<>(subset);
	        	newSubset.add(set.get(j));
	        	subsets.addAll(
	        			processLargerSubsets(set, newSubset, targetSize, j + 1));
	        }
	        return subsets;
	    }
	}
	
	@Override
	public String toString() {
		return "StartingData<total accounts "+
				this.pki.getAllAccounts().size()+
				"| total ads ids "+this.initializingUpdates.size()+">";
	}
		
}
