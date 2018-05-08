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
import java.util.stream.Collectors;

import bench.BootstrapMockSetup;
import mpt.core.Utils;
import mpt.dictionary.AuthenticatedDictionaryClient;
import mpt.dictionary.MPTDictionaryDelta;
import mpt.dictionary.MPTDictionaryFull;
import mpt.dictionary.MPTDictionaryPartial;
import pki.Account;
import pki.PKIDirectory;
import serialization.generated.BVerifyAPIMessageSerialization.ADSModification;
import serialization.generated.BVerifyAPIMessageSerialization.ADSRootProof;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import serialization.generated.BVerifyAPIMessageSerialization.Update;
import serialization.generated.MptSerialization.MerklePrefixTrie;

/**
 * MUST BE THREAD SAFE
 * @author henryaspegren
 *
 */
public class ADSManager {
	private static final Logger logger = Logger.getLogger(ADSManager.class.getName());
	private final ReadWriteLock lock = new ReentrantReadWriteLock();
		

	
	private final Map<String, ADSRootProof.Builder> adsRootProofs;
	private final List<MPTDictionaryDelta> deltas;
	
	private List<PerformUpdateRequest> stagedUpdates;
	private MPTDictionaryFull serverAuthADS;
	
	private List<byte[]> commitments;
	

	// CONSTANT MAPPINGS (these do not change!)
	// Java NOTE: cannot use byte[] as a key since
	//				implements referential equality so
	//				instead we wrap it with a string
	private final Map<String, Set<Account>> adsIdToOwners;
	private final Map<String, byte[]> adsIdStringToBytes;
	
	public ADSManager(String base, PKIDirectory pki) {
		this.stagedUpdates = new ArrayList<>();
		this.adsRootProofs = new HashMap<>();
		this.deltas = new ArrayList<>();
		this.commitments = new ArrayList<>();
		
		// (1) create a mapping from ADS_ID -> {owners}
		this.adsIdToOwners = new HashMap<>();
		this.adsIdStringToBytes = new HashMap<>();
		Set<Account> accounts = pki.getAllAccounts();
		for(Account a : accounts) {
			Set<byte[]> adsKeys = a.getADSKeys();
			for(byte[] adsKey : adsKeys) {
				// TODO check if other more efficientconversion from byte to string
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
		
		// (2) Second load the MASTER_ADS from disk
		this.serverAuthADS = BootstrapMockSetup.loadServerADS(base);
		logger.log(Level.INFO, "master ads loaded");

		// (3) Create initial update proofs 
		//		for each ADS
		for(Map.Entry<String, byte[]> adsId : this.adsIdStringToBytes.entrySet()) {
			byte[] adsIdByte = adsId.getValue();
			String adsIdString = adsId.getKey();
			AuthenticatedDictionaryClient mptPath = new MPTDictionaryPartial(this.serverAuthADS, adsIdByte);
			MerklePrefixTrie mptPathProof = mptPath.serialize();
			// note the proof only has the merkle paths
			// since at the start there hasn't been any updates
			ADSRootProof.Builder proof = ADSRootProof.newBuilder()
					.setLastUpdatedProof(mptPathProof);
			
			this.adsRootProofs.put(adsIdString, proof);	
		}
		logger.log(Level.INFO, "initial ads root proofs created");
		
		// (4) Do an initial commitment
		this.commit();
		logger.log(Level.INFO, "added an initial commitment");
		
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
	
	public void stageUpdate(PerformUpdateRequest approvedUpdate) {
		Update update = approvedUpdate.getUpdate();
		// make the changes to the ADS, but defer creating on the 
		// proof and actually committing the changes
		for(ADSModification modification : update.getModificationsList()) {
			byte[] adsId = modification.getAdsId().toByteArray();
			byte[] newRoot = modification.getNewValue().toByteArray();
			// store the proof
			this.serverAuthADS.insert(adsId, newRoot);
		}
		this.stagedUpdates.add(approvedUpdate);
	}
	
	public byte[] commit() {
		this.lock.writeLock().lock();
		// for each update
		// create and save a proof for all ADS_IDs changed
		for(PerformUpdateRequest approvedUpdate : this.stagedUpdates) {
			Update update = approvedUpdate.getUpdate();
			List<byte[]> adsIds = update.getModificationsList().stream()
					.map(x -> x.getAdsId().toByteArray())
					.collect(Collectors.toList());
			MPTDictionaryPartial paths = new MPTDictionaryPartial(this.serverAuthADS, adsIds);
			MerklePrefixTrie updatePerformedProof = paths.serialize();
			ADSRootProof.Builder proof = ADSRootProof.newBuilder()
					.setLastUpdate(approvedUpdate)
					.setLastUpdatedProof(updatePerformedProof);
			for(byte[] adsId : adsIds) {
				String adsIdString = Utils.byteArrayAsHexString(adsId);
				this.adsRootProofs.put(adsIdString, proof);
			}
		}
		
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
	

	public byte[] getValue(byte[] key) {
		this.lock.readLock().lock();
		byte[] value = this.serverAuthADS.get(key);
		this.lock.readLock().unlock();
		return value;
	}

	public byte[] currentCommitment() {
		this.lock.readLock().lock();
		byte[] currentCommitment = this.commitments.get(this.commitments.size());
		this.lock.readLock().unlock();
		return currentCommitment;
	}
	
	public byte[] getCommitment(int commitmentNumber) {
		this.lock.readLock().lock();
		byte[] commitment = null;
		if(commitmentNumber >= 0 && commitmentNumber < this.commitments.size()) {
			commitment = this.commitments.get(commitmentNumber);
		}
		this.lock.readLock().unlock();
		return commitment;
	}

}
