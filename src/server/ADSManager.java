package server;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import bench.BootstrapMockSetup;
import mpt.core.Utils;
import mpt.dictionary.MPTDictionaryDelta;
import mpt.dictionary.MPTDictionaryFull;
import mpt.dictionary.MPTDictionaryPartial;
import pki.Account;
import pki.PKIDirectory;
import serialization.generated.MptSerialization.MerklePrefixTrie;


public class ADSManager {
	private static final Logger logger = Logger.getLogger(ADSManager.class.getName());
	
	private final ReadWriteLock lock = new ReentrantReadWriteLock();
	
	// we store a mapping from ads_id 
	// to sets of clients who control the ADS.
	// The protocol requires that these 
	// clients must all sign updates to the ADS.
	// Java NOTE: cannot use byte[] as a key since
	//				implements referential equality so
	//				instead we wrap it with a string
	private final Map<String, Set<Account>> adsIdToOwners;
	private final Map<String, byte[]> adsIdStringToBytes;

	// current server authentication 
	// information. 
	// this is a mapping from a client ads id
	// to the root value of that ADS.
	private MPTDictionaryFull serverAuthADS;

	// we store the previous commitments
	// normally these would be witnessed
	// using the Bitcoin blockchain
	private List<byte[]> commitments;
	
	// we also store a log of changes to generate
	// proofs of updates
	private List<MPTDictionaryDelta> deltas;
	
	public ADSManager(String base, PKIDirectory pki) {
		this.deltas = new ArrayList<>();
		this.commitments = new ArrayList<>();
		
		// First create a mapping from ADS_ID
		// to the set of OWNERS
		this.adsIdToOwners = new HashMap<>();
		this.adsIdStringToBytes = new HashMap<>();
		Set<Account> accounts = pki.getAllAccounts();
		for(Account a : accounts) {
			Set<byte[]> adsKeys = a.getADSKeys();
			for(byte[] adsKey : adsKeys) {
				// TODO check if other more efficient matching
				String adsKeyString = Utils.byteArrayAsHexString(adsKey);
				this.adsIdStringToBytes.put(adsKeyString, adsKey);
				Set<Account> accs = this.adsIdToOwners.get(adsKeyString);
				if(accs == null) {
					accs = new HashSet<>();
				}
				accs.add(a);
				this.adsIdToOwners.put(adsKeyString, accs);
			}
		}
		logger.log(Level.INFO, "ads_id -> {owners} loaded");	
		// Second load the MASTER_ADS from disk
		this.serverAuthADS = BootstrapMockSetup.loadServerADS(base);
		
		logger.log(Level.INFO, "doing initial commitment");
		this.commit();
		
		logger.log(Level.INFO, "master ads loaded");
	}
	
	public Set<Account> getADSOwners(byte[] adsKey){
		String key = Utils.byteArrayAsHexString(adsKey);
		return new HashSet<Account>(this.adsIdToOwners.get(key));
	}
	
	public void update(byte[] adsKey, byte[] adsValue) {
		this.lock.writeLock().lock();
		this.serverAuthADS.insert(adsKey, adsValue);
		this.lock.writeLock().unlock();
	}
	
	public byte[] commit() {
		this.lock.writeLock().lock();
		// save delta
		MPTDictionaryDelta delta = new MPTDictionaryDelta(this.serverAuthADS);
		this.deltas.add(delta);
		// clear the changes
		this.serverAuthADS.reset();
		// calculate a new commitment 
		byte[] commitment = this.serverAuthADS.commitment();
		this.commitments.add(commitment);
		logger.log(Level.INFO, "commitment added!");
		this.lock.writeLock().unlock();
		return commitment;
	}

	public MerklePrefixTrie getProof(List<byte[]> keys) {
		this.lock.readLock().lock();
		MPTDictionaryPartial partial = new MPTDictionaryPartial(this.serverAuthADS, keys);
		this.lock.readLock().unlock();
		return partial.serialize();
	}
	

	public synchronized byte[] getValue(byte[] key) {
		this.lock.readLock().lock();
		byte[] value = this.serverAuthADS.get(key);
		this.lock.readLock().unlock();
		return value;
	}

	public synchronized byte[] currentCommitment() {
		this.lock.readLock().lock();
		byte[] currentCommitment = this.commitments.get(this.commitments.size());
		this.lock.readLock().unlock();
		return currentCommitment;
	}
	
	public synchronized byte[] getCommitment(int commitmentNumber) {
		this.lock.readLock().lock();
		byte[] commitment = null;
		if(commitmentNumber >= 0 && commitmentNumber < this.commitments.size()) {
			commitment = this.commitments.get(commitmentNumber);
		}
		this.lock.readLock().unlock();
		return commitment;
	}

}
