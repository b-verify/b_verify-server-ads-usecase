package server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import mpt.core.InvalidSerializationException;
import mpt.dictionary.MPTDictionaryDelta;
import mpt.dictionary.MPTDictionaryFull;
import mpt.dictionary.MPTDictionaryPartial;
import pki.Account;
import pki.PKIDirectory;
import serialization.generated.BVerifyAPIMessageSerialization.Updates;
import serialization.generated.MptSerialization.MerklePrefixTrie;


public class ADSManager {

	private final String base;
	
	// we store a mapping from adsKeys 
	// to sets of clients who control the ADS.
	// these clients must all sign to update
	// the ADS
	// Java NOTE: cannot use byte[] as a key since
	//				implements referential equality so
	//				instead we wrap it with a string
	private final Map<String, Set<Account>> adsKeyToOwners;

	// current server authentication 
	// information. 
	// this is a mapping from a client ads key 
	// (also referred to as ads id) to the 
	// root value of that ADS.
	private MPTDictionaryFull serverAuthADS;

	// we also store a log of changes to generate
	// proofs of updates
	// TODO: consider if we want to store these
	// or some subset of them on disk
	private List<MPTDictionaryDelta> deltas;
	
	
	public ADSManager(String base, PKIDirectory pki) {
		this.base = base;
		File f = new File(base + "server-ads/starting-ads");
		
		// First all the ADS Keys and 
		// determine which clients care about 
		// each ADS
		this.adsKeyToOwners = new HashMap<>();
		Set<Account> accounts = pki.getAllAccounts();
		for(Account a : accounts) {
			Set<byte[]> adsKeys = a.getADSKeys();
			for(byte[] adsKey : adsKeys) {
				String adsKeyString = new String(adsKey);
				Set<Account> accs = this.adsKeyToOwners.get(adsKeyString);
				if(accs == null) {
					accs = new HashSet<>();
				}
				accs.add(a);
				this.adsKeyToOwners.put(adsKeyString, accs);
			}
		}
		
		try {
			// Second load the Authentication ADS from disk
			FileInputStream fis = new FileInputStream(f);
			byte[] encodedAds = new byte[(int) f.length()];
			fis.read(encodedAds);
			fis.close();
			this.serverAuthADS = MPTDictionaryFull.deserialize(encodedAds);
		} catch (InvalidSerializationException | IOException e) {
			e.printStackTrace();
			throw new RuntimeException("corrupted data");
		}
		this.deltas = new ArrayList<>();
		System.out.println("ADSManager Loaded!");	
	}
	
	public Set<Account> getADSOwners(byte[] adsKey){
		return this.adsKeyToOwners.get(new String(adsKey));
	}
	
	public void update(byte[] adsKey, byte[] adsValue) {
		this.serverAuthADS.insert(adsKey, adsValue);
	}
	
	public byte[] commit() {
		// save delta
		MPTDictionaryDelta delta = new MPTDictionaryDelta(this.serverAuthADS);
		this.deltas.add(delta);
		// clear the changes
		this.serverAuthADS.reset();
		// calculate a new commitment 
		byte[] commitment = this.serverAuthADS.commitment();
		return commitment;
	}

	public byte[] get(byte[] key) {
		return this.serverAuthADS.get(key);
	}

	public byte[] commitment() {
		return this.serverAuthADS.commitment();
	}

	public MerklePrefixTrie getProof(List<byte[]> keys) {
		MPTDictionaryPartial partial = new MPTDictionaryPartial(this.serverAuthADS, keys);
		return partial.serialize();
	}

	public byte[] getUpdate(int startingCommitNumber, List<byte[]> keyHashes) {
		Updates.Builder updates = Updates.newBuilder();
		// go through each commitment
		for (int commitmentNumber = startingCommitNumber; commitmentNumber < this.deltas.size(); commitmentNumber++) {
			// get the changes
			MPTDictionaryDelta delta = this.deltas.get(commitmentNumber);
			// and calculate the updates
			MerklePrefixTrie update = delta.getUpdates(keyHashes);
			updates.addUpdate(update);
		}
		return updates.build().toByteArray();
	}

	public void save() {
		// TBD
		byte[] asBytes = this.serverAuthADS.serialize().toByteArray();
		try {
			File f = new File(base + "-" + this.serverAuthADS.commitment());
			FileOutputStream fos = new FileOutputStream(f);
			fos.write(asBytes);
			fos.close();
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}

}
